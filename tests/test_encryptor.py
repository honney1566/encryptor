from encryptor import *
import pytest


def createEncryptorOne():
    key =  get_random_bytes(16)
    print(key)
    return Encryptor(key = key) , key

def createEncryptorTwo():
    key=get_random_bytes(16)
    return Encryptor(mode='CAST', key = key), key

@pytest.fixture(scope='function')
def createBlankFileForTest():
    path = 'testFile.txt'
    with open(path, 'wb') as f:
        f.write('Nudes'.encode('utf-8'))
    yield path
    os.remove(path)
    
def createOnExitDebug():    
    key = get_random_bytes(16)
    enc = Encryptor(key=key, debug=True, debugCatchList=['error-on-exit'])
    return enc

def createMidEncryptionDebug():
    key = get_random_bytes(16)
    enc = Encryptor(key=key, debug=True, debugCatchList=['error-mid-encryption'])
    return enc


@pytest.mark.parametrize('encryptor', [createEncryptorOne])
class Test_black:
    """
    Test suite:
        1) Happy path.
        2) Key type is not applicable.
        3) Encryption
        3.1) Data is passed in bad way (Types, way, corrupted, etc)
        3.2) File for proccess is not a file actually.
        4) Decryption
        4.1) Data is passed in bad way (Types, way, corrupted, etc)
        4.2) File for proccess is not a file actually.
        4.3) Swap key
    """
    def test_happy_path(self, encryptor, createBlankFileForTest):
        """
        Encrypt -- decrypt 
        Expect: Data remains the same. But encrypted is not the same as original.
        """
        enc, _ = encryptor()
        testingPath = createBlankFileForTest
        with open(testingPath, 'rb') as f:
            originalData = f.read(-1)
        encryptedData = enc.encrypt(testingPath)
        with open(os.path.join(os.getcwd(), "MyEncryptedFile.txt"), 'wb') as f:
            f.write(encryptedData)
        decrypted = enc.decrypt(os.path.join(os.getcwd(), "MyEncryptedFile.txt"))
        os.remove(os.path.join(os.getcwd(), "MyEncryptedFile.txt"))
        assert encryptedData != originalData, "It doesn't work. The encrypted data is the same as original!"
        assert decrypted == originalData, "The encryptor changed the data." 
        
    @pytest.mark.parametrize('key', ('hello!', 11, [])) # Feel free to expand
    def test_bad_key(self, key, encryptor, createBlankFileForTest):
        """
        Try passing bad key. Expect Value Error
        """
        enc, _  = encryptor()
        path = createBlankFileForTest
        with pytest.raises(ValueError):
            enc.key = key 
            enc.encrypt(path)

    @pytest.mark.parametrize('data', ([], None, 'NonexistingFile.txt'))
    def test_encryption_bad_data(self, encryptor, data):
        """
        Try passing bad data for encryption(format). Expect Value Error
        """
        enc, _ = encryptor()
        with pytest.raises(ValueError):
            enc.encrypt(data)        
    
    @pytest.mark.parametrize('data',([], None, 'NonexistingFile.txt'))
    def test_decryption_badData(self, encryptor, data):
        """
        Try passing bad data for decryption(format). Expect Value Error
        """
        enc, _ = encryptor()
        with pytest.raises(ValueError):
            enc.decrypt(data)
            
    def test_decryption(self, encryptor, createBlankFileForTest):
        """
        Substitute key for decryption. Shall recieve Value Error. 
        """
        enc, key = encryptor()
        testingPath = createBlankFileForTest
        with open(testingPath, 'rb') as f:
            originalData = f.read(-1)
        data = enc.encrypt(testingPath)
        with open(os.path.join(os.getcwd(),'encrytedFile.txt'), 'wb') as f:
            f.write(data)
        with pytest.raises(ValueError):
            assert enc.decrypt(os.path.join(os.getcwd(),'encrytedFile.txt')) == originalData
            enc.key = get_random_bytes(16)
            enc.decrypt('encrytedFile.txt')

class Test_white:
    def test_catch_on_exitError(self, createBlankFileForTest):
        enc = createOnExitDebug()
        path = createBlankFileForTest
        with pytest.raises(onExitError):
            enc.encrypt(path)
            
    def test_catch_midEncryption(self, createBlankFileForTest):
        enc = createMidEncryptionDebug()
        path = createBlankFileForTest
        with pytest.raises(midEncrError):
            enc.encrypt(path)   