from test_utils import * 

def test_request():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file1 = os.path.join(base_dir, "file1.txt")
    file2 = os.path.join(base_dir, "file2.txt")
    target_filepath = os.path.join(base_dir, "..\socket_programming\client-files\hello2.txt")
    model_filepath = os.path.join(base_dir, "testfiles\hello2.txt")
    launch_request("vinitg", "REQUEST", "hello", ["1"])
    with open(target_filepath, "rb") as f1, open(model_filepath, "rb") as f2:
        content1 = f1.read()
        content2 = f2.read()
        assert content1 == content2, "The contents of the files do not match!"

def test_store(): 
    pass
    # launch STORE request 
    # scp original file to fileserver
    # launch (via powershell remoting) diff command b/w the two files
    # assert captured output to show identical files 

def test_P2P(): 
    pass
    # launch STORE local -> fileserver
    # launch REQUEST fileserver -> some other client
    # scp original file to client 
    # diff b/w them 
