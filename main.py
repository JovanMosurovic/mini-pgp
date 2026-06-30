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


def main():
    print("=" * 80)
    print("  MiniPGP - test prstenova kljuceva")
    print("=" * 80)

    private_ring = PrivateKeyRing()
    public_ring = PublicKeyRing()

    # [1] Generisanje parova ------------------------------------------------
    print("\n[1] Generisanje RSA parova (idu u privatni prsten)")
    alisa_id = private_ring.add("Alisa", "alisa@example.com", 1024, "alisa-lozinka")
    bob_id = private_ring.add("Bob", "bob@example.com", 2048, "bob-lozinka")
    print(f"    + Alisa -> Key ID {alisa_id}")
    print(f"    + Bob   -> Key ID {bob_id}")
    print_ring("Prsten privatnih kljuceva", private_ring)

    # [2] Pristup privatnom kljucu uz lozinku -------------------------------
    print("\n[2] Pristup privatnom kljucu (uvek trazi lozinku)")
    poruka = b"Zdravo, ovo je test poruka."

    privatni = private_ring.get_private_key(alisa_id, "alisa-lozinka")
    potpis = rsa_sign(privatni, poruka)
    javni = load_public_pem(private_ring.get(alisa_id)["public_key_pem"].encode())
    print(f"    tacna lozinka  -> potpis kreiran ({len(potpis)} B), "
          f"verifikacija = {rsa_verify(javni, poruka, potpis)}")

    try:
        private_ring.get_private_key(alisa_id, "pogresna-lozinka")
    except ValueError as e:
        print(f"    pogresna lozinka -> greska uhvacena: {e}")

    # [3] Uvoz javnog kljuca u javni prsten ---------------------------------
    print("\n[3] Uvoz javnog kljuca u javni prsten")
    bobov_javni = load_public_pem(private_ring.get(bob_id)["public_key_pem"].encode())
    public_ring.add("Bob", "bob@example.com", bobov_javni)
    public_ring.add("Bob", "bob@example.com", bobov_javni)  # isti opet -> bez duplikata
    print("    + uvezen Bobov javni kljuc (dvaput -> ostaje jedan unos)")
    print_ring("Prsten javnih kljuceva", public_ring)

    # [4] Cuvanje na disk i ucitavanje (JSON) -------------------------------
    print("\n[4] Cuvanje i ucitavanje prstena (JSON perzistencija)")
    putanja = "keyrings_demo.json"
    private_ring.save(putanja)
    novi = PrivateKeyRing()
    novi.load(putanja)
    privatni2 = novi.get_private_key(alisa_id, "alisa-lozinka")
    radi = rsa_verify(javni, poruka, rsa_sign(privatni2, poruka))
    print(f"    sacuvano u '{putanja}', ucitano {len(novi._by_id)} kljuc/a, "
          f"kljuc radi posle reload-a = {radi}")
    print(f"    (otvori '{putanja}' da vidis kako prsten izgleda u JSON-u)")

    # [5] Brisanje ----------------------------------------------------------
    print("\n[5] Brisanje kljuca iz prstena")
    private_ring.remove(bob_id)
    print(f"    obrisan Bob -> ostalo {len(private_ring._by_id)} privatnih kljuceva")

    print("\n" + "=" * 80)
    print("  Gotovo.")
    print("=" * 80)

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