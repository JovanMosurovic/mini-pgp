# MiniPGP Quick Manual Test

This document describes a short manual test flow for the MiniPGP GUI.

## Run the Application

Run from the project root:

```bash
.venv/bin/python -c "from gui.app import MiniPGPApp; MiniPGPApp().mainloop()"
```

## Test Messages

Use any of these input files:

- `test_files/01_short_serbian.txt`
- `test_files/02_short_english.txt`
- `test_files/03_long_serbian.txt`
- `test_files/04_long_english.txt`

Save generated `.pgp` files and recovered plaintext files in:

```text
test_output/
```

## 1. Generate a Test Key

1. Open the `Kljucevi` tab.
2. Enter:
   - `Ime`: `Test User`
   - `Email`: `test@example.com`
   - `Velicina RSA kljuca`: `1024`
   - `Lozinka za privatni kljuc`: `test1234`
3. Click `Generisi par kljuceva`.
4. Confirm that the key appears in both key rings.

For a simple local test, the same generated key can be used for signing and
receiving.

## 2. Create a PGP File

1. Open the `Slanje` tab.
2. Select an input file, for example:
   - `test_files/03_long_serbian.txt`
3. Select an output file, for example:
   - `test_output/long_serbian.pgp`
4. Enable:
   - `Potpisivanje`
   - `Enkripcija`
   - `Kompresija`
   - `Radix-64/base64 omotac`
5. Select the generated private key for signing.
6. Enter `test1234` as the private key password.
7. Select the generated public key as the recipient key.
8. Click `Kreiraj PGP datoteku`.

Expected result: a `.pgp` file is created in `test_output/`.

## 3. Receive the PGP File

1. Open the `Prijem` tab.
2. Select the generated `.pgp` file.
3. Leave `Kljuc primaoca` as `automatski po Key ID`, or select the generated
   private key.
4. Enter `test1234`.
5. Click `Obradi PGP datoteku`.

Expected result:

- `Prepoznati paketi` is updated.
- `Verifikacija potpisa` is `ispravan` when signing was enabled.
- `Originalna poruka` displays the original message text.

## 4. Save the Recovered Message

1. Select a destination such as:
   - `test_output/recovered_long_serbian.txt`
2. Click `Sacuvaj originalnu poruku`.
3. Compare the recovered file with the original input file.

## Quick Variations

- Run with all four services enabled.
- Run with only `Potpisivanje` enabled.
- Run with only `Enkripcija` enabled.
- Run once with `Radix-64/base64 omotac` disabled.
- Try receiving an encrypted file with a wrong password; an error dialog should
  appear.
