from gui.app import MiniPGPApp
from core.keyrings import PrivateKeyRing

def main():
    app = MiniPGPApp()
    app.mainloop()


if __name__ == "__main__":
    #graphics
    # main()
    # tests
    pkr = PrivateKeyRing()
    pkr.add("Aleksandar", "aleksandar03avramovic@gmail.com", 1024, "test1234")
    pkr.add("DAsd", "aleksandar03avramovic@gmail.com", 1024, "test1234")
    entry = pkr.find("Aleksandar")
    print(entry)
    pkr.remove("Aleksandar")
    entry = pkr.find("Aleksandar")
    print(entry)
    pkr.print_all()