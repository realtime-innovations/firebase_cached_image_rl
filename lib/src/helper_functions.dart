import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_storage/firebase_storage.dart';
import 'package:uuid/uuid.dart';

Uri getUrlFromRef(Reference ref) {
  final link = "gs://${ref.bucket}/${ref.fullPath}";
  return Uri.parse(link);
}

String getBucketFromUrl(Uri url) => '${url.scheme}://${url.authority}';

Reference getRefFromUrl(String url, FirebaseApp? app) {
  return FirebaseStorage.instanceFor(app: app).refFromURL(url);
}

String getUniqueId(String url) {
  return const Uuid().v5(Uuid.NAMESPACE_URL, url);
}

/// Decrypts data - automatically detects and handles both full and partial encryption
///
/// Detects format by checking for "PART" magic header:
/// - With "PART": Decrypts using partial format (header + tail only)
/// - Without "PART": Decrypts entire data (legacy/full encryption)
Uint8List decryptBytes(
    Uint8List encryptedDataWithIV,
    String encryptedSecret,
  ) {
    final encryptor = _getEncryptor(encryptedSecret);
    
    // Check for "PART" magic header to determine encryption type
    final bool isPartialEncryption = encryptedDataWithIV.length > 4 &&
        encryptedDataWithIV[0] == 0x50 && // P
        encryptedDataWithIV[1] == 0x41 && // A
        encryptedDataWithIV[2] == 0x52 && // R
        encryptedDataWithIV[3] == 0x54;   // T
    
    List<int> result;
    
    if (isPartialEncryption) {
      // PARTIAL DECRYPTION - parse custom format
      print('[firebase_cached_image] Decrypting partial format');
      int offset = 4; // Skip "PART" header
      
      // Extract components from the format
      final iv = IV(encryptedDataWithIV.sublist(offset, offset + 16));
      offset += 16;
      
      final headerSize = _bytesToInt(encryptedDataWithIV.sublist(offset, offset + 4));
      offset += 4;
      
      final tailSize = _bytesToInt(encryptedDataWithIV.sublist(offset, offset + 4));
      offset += 4;
      
      // Extract encrypted header
      final encryptedHeader = encryptedDataWithIV.sublist(offset, offset + headerSize);
      offset += headerSize;
      
      // Extract unencrypted middle
      final middleSize = encryptedDataWithIV.length - offset - tailSize;
      final middle = encryptedDataWithIV.sublist(offset, offset + middleSize);
      offset += middleSize;
      
      // Extract encrypted tail
      final encryptedTail = encryptedDataWithIV.sublist(offset);
      
      // Decrypt header and tail, keep middle as-is
      result = [
        ...encryptor.decryptBytes(Encrypted(encryptedHeader), iv: iv),
        ...middle,
        ...encryptor.decryptBytes(Encrypted(encryptedTail), iv: iv),
      ];
    } else {
      // FULL DECRYPTION - standard AES-CBC with IV prefix
      print('[firebase_cached_image] Decrypting full format');
      final iv = IV(encryptedDataWithIV.sublist(0, 16));
      final encryptedData = Encrypted(encryptedDataWithIV.sublist(16));
      
      result = encryptor.decryptBytes(encryptedData, iv: iv);
    }
    
    return Uint8List.fromList(result);
  }

  Encrypter _getEncryptor(String base64HexKey) {
    final key = Key.fromBase64(base64HexKey);
    return Encrypter(AES(key, mode: AESMode.cbc, padding: 'PKCS7'));
  }
  
  int _bytesToInt(List<int> bytes) =>
      (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
