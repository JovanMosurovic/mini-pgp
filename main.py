from core.crypto import rsa_verify, load_public_pem, rsa_sign
from gui.app import MiniPGPApp
from core.keyrings import PrivateKeyRing, PublicKeyRing


def main():
    app = MiniPGPApp()
    app.mainloop()

def print_ring(naslov, ring):
    print(f"\n  {naslov}  ({len(ring._by_id)} kljuc/a)")
    print("  " + "-" * 78)
    print("  {:<16} {:<16} {:<12} {:<24} {}".format(
        "Timestamp", "Key ID", "Ime", "Email", "RSA"))
    print("  " + "-" * 78)
    for ts, kid, name, email, bits in ring.to_rows():
        print("  {:<16} {:<16} {:<12} {:<24} {}".format(ts, kid, name, email, bits))
    print("  " + "-" * 78)


if __name__ == "__main__":
    #graphics
    main()
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