/**
 * Copyright (c) 2020 Romulo Fernandes Machado Leitao <abra185@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "crc.h"
#include "ftdi.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <sstream>
#include <thread>

namespace fs = std::filesystem;

class Exception : public std::exception {
public:
  Exception(const std::string& reason) : reason(reason) {}
  const char* what() const throw() override {
    return reason.c_str();
  }

  std::string reason;
};

#define log(X) do {\
  std::stringstream __str;\
  __str << X;\
  std::cout << __str.str() << std::endl;\
} while (false)\

#define throwException(X) do {\
  std::stringstream __str;\
  __str << X;\
  throw Exception(__str.str());\
} while (false)\

#define throwUsbException(X) do {\
  std::stringstream __str;\
  __str << X << " - Reason: " << ftdi_get_error_string(ftdiContext);\
  throw Exception(__str.str());\
} while (false)\

#define USB_READPACKET_SIZE (64*1024)
#define USB_WRITEPACKET_SIZE (4*1024)

uint32_t toBE(uint32_t le) {
  return ((le >> 24) & 0xFF) 
    | ((le >> 8 & 0xFF) << 16)
    | ((le >> 16 & 0xFF) << 8)
    | ((le & 0xFF) << 24);
}

uint32_t calculateHash(const std::string& str) {
  uint32_t prime = 31;
  uint32_t cutNumber = 1000000009;
  uint32_t hash = 0;

  for (char c : str) {
    hash += (c - 31) * prime;
    hash %= cutNumber;

    prime *= 31;
  }

  return hash;
}

inline fs::path fixPath(const fs::path& path) {
  std::string result;
  for (char c : path.string()) {
    char newChar = ::toupper(c);
    if (newChar == '\\')
      newChar = '/';

    result += newChar;
  }

  return fs::path(result);
}

std::unordered_map<uint32_t, fs::path> generateFilenameEntries() {
  std::unordered_map<uint32_t, fs::path> result;

  fs::path cdDir("./cd/");
  if (!fs::exists(cdDir))
    throwException("'cd' directory does not exist!");

  for (auto &entry : fs::recursive_directory_iterator(cdDir)) {
    const fs::path &entryPath = entry.path();
    if (fs::is_directory(entryPath))
      continue;

    fs::path relativePath;
    std::size_t subPathCount = 0;
    for (auto& subPath : entryPath) {
      if (subPathCount < 2) {
        subPathCount++;
        continue;
      }

      relativePath /= subPath;
    }

    // Calculate hash.
    const std::string upperString = fixPath(relativePath).string();
    const uint32_t hash = calculateHash(upperString);

    log(upperString << " - " << hash);
    if (result.find(hash) != result.end()) {
      throwException("Hash " << hash << " already exists for filename " << 
        result[hash].string());
    }

    result[hash] = entryPath;
  }

  return result;
}

void initUSB(ftdi_context *ftdiContext) {
  if (ftdi_init(ftdiContext) != 0)
    throwUsbException("Failed to initialize ftdi context.");
  
  const int vendorID = 0x0403; 
  const int productID = 0x6001;
  if (ftdi_usb_open(ftdiContext, vendorID, productID))
    throwUsbException("Failed to open usb.");
      
  try {
    if (ftdi_usb_purge_buffers(ftdiContext))
      throwUsbException("Failed to purge buffers.");

    if (ftdi_read_data_set_chunksize(ftdiContext, USB_READPACKET_SIZE))
      throwUsbException("Failed to set read chunksize.");

    if (ftdi_write_data_set_chunksize(ftdiContext, USB_WRITEPACKET_SIZE))
      throwUsbException("Failed to set write chunksize.");

    if (ftdi_set_bitmode(ftdiContext, 0x0, BITMODE_RESET))
      throwUsbException("Failed to set bitmode.");

  } catch (...) {
    ftdi_usb_close(ftdiContext);
    throw;
  }
}

void deinitUSB(ftdi_context *ftdiContext) {
  ftdi_usb_purge_buffers(ftdiContext);
  ftdi_usb_close(ftdiContext);
}

struct File {
  std::unique_ptr<unsigned char[]> dataPtr;
  std::size_t size;

  inline unsigned char* data() { return dataPtr.get(); }
};

File readFile(const fs::path &filename) {
  // Read file data first.
  std::ifstream file(filename.string().c_str(), 
    std::ios::binary | std::ios::in | std::ios::ate);

  if (!file.is_open())
    throwException("Failed to open filename " << filename.string());

  File resultFile;
  resultFile.size = file.tellg();
  file.seekg(std::ios::beg);

  resultFile.dataPtr = std::make_unique<unsigned char[]>(resultFile.size);
  file.read((char*)resultFile.data(), resultFile.size);

  return resultFile;
}

uint8_t getFileCRC(const File& file) {
  crc_t crc = crc_init();
  crc = crc_update(crc, (const unsigned char*) file.data(), file.size);
  return crc_finalize(crc);
}

void sendBinary(const fs::path &binaryPath, ftdi_context *ftdiContext) {

  // Read file data first.
  File fileData = readFile(binaryPath);

  // Calculate file crc.
  const uint8_t fileCRC = getFileCRC(fileData);
  std::cout << "  - Read " << fileData.size << " bytes with CRC = " << 
    (uint32_t) fileCRC << std::endl;

  // PC sends execute address (4 bytes)
  // PC sends data length     (4 bytes)
  // PC sends reset flags     (4 bytes)
  // PC sends data            (variable length)
  // PC sends CRC             (1 byte)
  // Saturn sends CRC check   (1 byte, 0: CRC match, else: CRC mismatch)
  const uint32_t destAddress = toBE(0x06004000);
  const uint32_t dataLength = toBE((uint32_t)fileData.size);
  const uint32_t resetFlags = toBE(0);

  unsigned char tmpBuffer[12];
  memcpy(tmpBuffer + 0, &destAddress, sizeof(uint32_t));
  memcpy(tmpBuffer + 4, &dataLength, sizeof(uint32_t));
  memcpy(tmpBuffer + 8, &resetFlags, sizeof(uint32_t));

  // Upload and execute function.
  unsigned char execFunction = 0x06;
  if (ftdi_write_data(ftdiContext, &execFunction, 1) < 0) 
    throwException("Failed to send 'upload & execute' command.");

  if (ftdi_write_data(ftdiContext, tmpBuffer, 12) < 0) 
    throwException("Failed to send USB header.");

  std::cout << "  - Sending file data..." << std::endl;
  fflush(stdout);

  if (ftdi_write_data(ftdiContext, fileData.data(), fileData.size) < 0) 
    throwException("Failed to send file data.");

  if (ftdi_write_data(ftdiContext, &fileCRC, 1) < 0) 
    throwException("Failed to send CRC.");

  uint8_t checkCRC = 0xFF;
  int readDataStatus = 0;
  do {
    readDataStatus = ftdi_read_data(ftdiContext, &checkCRC, 1);
    if (readDataStatus > 0 && checkCRC != 0)
      throwException("Transfer failed: CRC's do not match.");
  } while (readDataStatus == 0);

  log("Transfer Successful!");
}

enum TransferCommands {
  TC_REQUEST_FILE = 0,
  TC_REQUEST_FILE_SIZE,
  TC_INVALID = 0xFF
};

/**
 * Client requested a file.
 */
void requestFileAction(ftdi_context *ftdiContext, 
  const std::unordered_map<uint32_t, fs::path> &fileEntries) {

  typedef unsigned char uchar;
  uint32_t fileHash = 0;

  // Read file hash first.
  int status = 0;
  do {
    uint32_t data;
    status = ftdi_read_data(ftdiContext, (uchar*) &data, 4);
    if (status < 0)
      throwUsbException("Failed to receive file hash.");

    fileHash = toBE(data);
  } while (status == 0);

  // We answer by sending:
  // - File Size (4 bytes)
  // - Data
  // - CRC (1 byte)
  auto fileIt = fileEntries.find(fileHash);
  if (fileIt == fileEntries.end()) {
    log("Requested filename with hash " << fileHash << " does not exist.");

    // File does not exist.
    uint32_t doesNotExist = 0;
    if (ftdi_write_data(ftdiContext, (uchar*) &doesNotExist, 4) < 0)
      throwUsbException("Failed to write 'does not exist' data.");

  } else {
    const fs::path filePath = fileIt->second;
    File fileData = readFile(filePath);

    const uint8_t fileCRC = getFileCRC(fileData);
    std::cout << "Read file " << filePath.string() << " (crc = " << 
      (int)fileCRC << ") sending...";

    fflush(stdout);

    const uint32_t fileSize = toBE(fileData.size);
    if (ftdi_write_data(ftdiContext, (uchar*) &fileSize, 4) < 0)
      throwUsbException("Failed to send file size.");
    
    if (ftdi_write_data(ftdiContext, fileData.data(), fileData.size) < 0)
      throwUsbException("Failed to send file contents.");

    if (ftdi_write_data(ftdiContext, (uchar*) &fileCRC, 1) < 0)
      throwUsbException("Failed to send file CRC.");

    // Read CRC status (0 = fine).
    int status = 0;
    do {
      uint8_t data;
      status = ftdi_read_data(ftdiContext, &data, 1);
      if (status < 0)
        throwUsbException("Failed to receive transfer CRC status.");
      else if (status > 0 && data != 0)
        log("Transfer failed, CRC doesn't match.");

    } while (status == 0);

    std::cout << "Done!" << std::endl;
  }
}

/**
 * Client requested a file size.
 */
void requestFileSizeAction(ftdi_context *ftdiContext, 
  const std::unordered_map<uint32_t, fs::path> &fileEntries) {

  typedef unsigned char uchar;
  uint32_t fileHash = 0;

  // Read file hash first.
  int status = 0;
  do {
    uint32_t data;
    status = ftdi_read_data(ftdiContext, (uchar*) &data, 4);
    if (status < 0)
      throwUsbException("Failed to receive file hash.");

    fileHash = toBE(data);
  } while (status == 0);

  // We answer by sending:
  // - File Size (4 bytes)
  auto fileIt = fileEntries.find(fileHash);
  if (fileIt == fileEntries.end()) {
    log("Requested filename with hash " << fileHash << " does not exist.");

    // File does not exist.
    uint32_t doesNotExist = 0;
    if (ftdi_write_data(ftdiContext, (uchar*) &doesNotExist, 4) < 0)
      throwUsbException("Failed to write 'does not exist' data.");

  } else {
    const fs::path filePath = fileIt->second;
    std::ifstream file(filePath.string().c_str(),
      std::ios::binary | std::ios::in | std::ios::ate);

    if (!file.is_open())
      throwException("Failed to open filename " << filePath.string());

    const uint32_t fileSize = (uint32_t) file.tellg();
    std::cout << "Read file " << filePath.string() << " (size = " << 
      fileSize << ") sending size...";
    fflush(stdout);

    const uint32_t fileSizeBE = toBE(fileSize);
    if (ftdi_write_data(ftdiContext, (uchar*) &fileSizeBE, 4) < 0)
      throwUsbException("Failed to send file size.");

    std::cout << "Done!" << std::endl;
  }
}

/**
 * Wait for commands on the USB slot and transfer files when requested.
 */
void serveFiles(ftdi_context *ftdiContext, 
  const std::unordered_map<uint32_t, fs::path> &fileEntries) {

  while (true) {
    uint8_t commandAction = 0xFF;
    const int status = ftdi_read_data(ftdiContext, &commandAction, 1);
    if (status < 0) {
      throwUsbException("Failed to receive command.");
    } else if (status == 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }


    switch (commandAction) {
    case TC_REQUEST_FILE:
      requestFileAction(ftdiContext, fileEntries);
      break;
    case TC_REQUEST_FILE_SIZE:
      requestFileSizeAction(ftdiContext, fileEntries);
      break;
    default:
    case TC_INVALID:
      log("Received invalid command action: " << (uint32_t)commandAction);
      break;
    }
  }
}

int main(int argc, const char **argv) {
  log("Current 'cd' directory will be served");

  if (argc < 2) {
    log("Usage usb_dev_tool.exe filename.bin");
    return -1;
  }

  fs::path binaryPath(argv[1]);
  if (!fs::exists(binaryPath)) {
    log("Filename \"" << binaryPath.string() << "\" does not exist.");
    return -1;
  }

  // Read 'cd' directory.
  ftdi_context ftdiContext;
  memset(&ftdiContext, 0, sizeof(ftdi_context));

  try {
    auto cdEntries = generateFilenameEntries();
    initUSB(&ftdiContext);

    log("Sending \"" << binaryPath.string() << "\"...");
    sendBinary(binaryPath, &ftdiContext);
    serveFiles(&ftdiContext, cdEntries);

  } catch (std::exception &e) {
    log("Error: " << e.what());
    return -1;

  } catch (...) {
    log("Unknown error detected.");
    return -1;
  }

  deinitUSB(&ftdiContext);
  return 0;
}
