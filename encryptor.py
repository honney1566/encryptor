"""

A small Python application encrypting and decrypting files using a symmetric key. The app should be able to encrypt files using at least two different encryption
algorithms and support the encryption of large files (taking memory consumption into consideration). 

App should also accept parameters which will cause it to simulate errors during
the encryption for future testing purposes (i.e. --error-mid-encryption, --error-on-exit).

The encrypting app should then be tested by a second, test application. 
Please present both black and white box forms of testing.
Some tests should be sensitive not only to the app's final product but also to the standard output it provides during the encryption process (errors,
progress, unexpected exit). 

Test results should be provided in a very minimalistic and transparent way by using the test report framework (Allure).

Both applications should be properly packaged using the tools of your choice and structured in a way which supports app extensibility in the future.

This exercise should not be focused on the encryption features but rather on combining the whole testing flow, showing your coding manner and proficiency in using several frameworks.

Hence, the symmetric key should be provided either via file or as a standard input parameter in a plain text form.
"""
import os
from typing import Any
from Crypto.Cipher import AES, CAST
from Crypto.Random import get_random_bytes
from enum import Enum

class midEncrError(Exception):
    pass

class onExitError(Exception):
    pass

class Encryptor:
    def __init__(self, mode:str = 'AES', key:str = b'', allowedSize:int = 4096, debug:bool = False, debugCatchList:list = []) -> None:
        self.mode = mode # Encryption algorithm
        if isinstance(key,str) and os.path.exists(key):
            # File file exists. Assume its a file containing the key.
            with open(key, 'rb') as f:
                self.key = f.read(-1)
        else:
            self.key = key         
        # Size to proccess at once. If the file is bigger than this number -> split in chunks and procces sequently.
        self.allowedSize = allowedSize if isinstance(allowedSize, int) else 4096
        self.debug = debug # Debug mode on / off.
        # The list of errors which the program will simulate IF ONLY the debug flag is True 
        self.debugCatchList = debugCatchList if isinstance(debugCatchList, list) else []
        if self.mode == 'AES':
            self.__class__ = AES_cryptor
        elif self.mode == 'CAST':
            self.__class__ = CAST_cryptor
        else:
            print('Do not know this encryptor... Using default') # Depends on business rules
            self.__class__ = AES_cryptor
        
    def encrypt(self, file) -> bool:
        if self.debug and 'error-mid-encryption' in self.debugCatchList:
            raise midEncrError
        try:
            with open(file) as f:
                data = f.read(-1).encode('utf-8')
                result = self._processEncrypt(data)
                if self.debug and 'error-on-exit' in self.debugCatchList:
                    raise onExitError                    
                return result
        except onExitError as e:
            raise e
        except FileNotFoundError:
            raise ValueError
        except TypeError:
            raise ValueError
        except Exception as e:
            print(e)
            raise e            
        
    def decrypt(self, data) -> bool:
        if self.debug and 'error-mid-encryption' in self.debugCatchList:
            raise midEncrError
        try:
            with open(data) as f:
                data = f.read(-1).encode('utf-8')
                result = self._processDecrypt(data) 
                if self.debug and 'error-on-exit' in self.debugCatchList:
                    raise onExitError                    
                return result
        except FileNotFoundError:
            raise ValueError
        except TypeError:
            raise ValueError
        except Exception as e:
            raise e            
        
    @property
    def key(self):
        return self._key
    
    @key.setter
    def key(self, newKey):
        if not isinstance(newKey, bytes):
            raise ValueError
        else: 
            self._key = newKey    
        
class AES_cryptor (Encryptor):
    def __init__(self, file, mode: str = 'AES', key: bytes = b'', allowedSize: int = 4096, debug: bool = False, debugCatchList: list = []) -> None:
        super().__init__(file, mode, key, allowedSize, debug, debugCatchList)
    
    def _processEncrypt(self, data) -> bytearray:
        cipher = AES.new(self._key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        self.nonce = nonce
        self.tag = tag
        return ciphertext
            
    def _processDecrypt(self, data) -> bool:
        cipher = AES.new(self._key, AES.MODE_EAX, nonce=self.nonce)
        plaintext = cipher.decrypt(data)
        try:
            cipher.verify(self.tag)
            return plaintext
        except ValueError:
            raise ValueError
        except Exception as e:
            print(e)
            raise e
    

class CAST_cryptor(Encryptor):
    def __init__(self, mode: str = 'AES', key: bytes = b'', allowedSize: int = 4096, debug: bool = False, debugCatchList: list = []) -> None:
        super().__init__(mode, key, allowedSize, debug, debugCatchList)
        
    def _processEncrypt(self, data) -> bool:
        cipher = CAST.new(self._key, CAST.MODE_ECB)
        encrypted_data = cipher.encrypt(data)
        return encrypted_data
        
    def _processDecrypt(self, text) -> bool:
        cipher = CAST.new(self._key, CAST.MODE_ECB)
        decrypted_data = cipher.decrypt(text)
        return decrypted_data

