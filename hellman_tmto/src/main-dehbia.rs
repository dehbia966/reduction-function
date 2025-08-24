use clap::Parser;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::env;
use std::fs::{self, File};
use std::io::{Write, BufWriter};
use std::thread;
use rand_chacha::ChaCha20Rng;
use rand::{Rng, SeedableRng};

const MAX_DOMAIN:  u64 = 274877906943; // 2**38 - 1

fn generated_aleatoire_passwords(nchains:u64)->Vec<u64> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut result: Vec<u64>= Vec::with_capacity(nchains as usize);
    while result.len()< nchains as usize {
        let candidat = rng.gen_range(0..=MAX_DOMAIN);
        if !result.contains(&candidat){
            result.push(candidat);
        }

    }
    result
}

fn reduction_function(password: &[u8; 32], rotation: u8) -> u64 {
    // ---- Étape 1 : rotation circulaire à droite ----
    // On décompose la rotation totale N en :
    // - byte_shift : nombre d'octets (groupes de 8 bits) à décaler.
    // - bit_shift  : reste en bits à décaler.
    // Exemple : N = 13 → byte_shift = 1, bit_shift = 5.

    let byte_shift = (rotation / 8) as usize; // nombre d'octets à décaler (0..31)
    let bit_shift  = (rotation % 8) as u32;   // nombre de bits  à décaler (0..7)

    // ---- 1a) Rotation à droite par octets ----
    let mut tmp1 = [0u8; 32];                 // tampon après rotation par octets
    if byte_shift == 0 {
        tmp1 = *password;                     // aucun décalage d'octet : copie directe
    } else {
        for j in 0..32 {
            // Décalage circulaire : l'octet qui "sort" par la droite revient à gauche.
            // (j + 32 - byte_shift) % 32 = index source pour remplir tmp1[j].
            tmp1[j] = password[(j + 32 - byte_shift) % 32];
            // (Pour une rotation à GAUCHE : password[(j + 32 + byte_shift) % 32])
        }
    }

    // ---- 1b) Rotation à droite au niveau des bits ----
    let mut tmp2 = [0u8; 32];                 // tampon final après rotation bits
    if bit_shift == 0 {
        tmp2 = tmp1;                          // aucun décalage de bits : copie directe
    } else {
        for j in 0..32 {
            // Formule classique de rotate-right (circulaire) sur 8 bits :
            // out[j] = (tmp1[j] >> s) | (tmp1[j-1] << (8 - s)), avec j-1 circulaire.
            let hi = tmp1[j] >> bit_shift;                    // partie haute (bits qui restent dans l'octet courant)
            let lo = tmp1[(j + 31) % 32] << (8 - bit_shift);  // partie basse récupérée de l'octet précédent (circulaire)
            tmp2[j] = hi | lo;                                // recomposition de l'octet tourné
            // (Pour une rotation à GAUCHE : hi = tmp1[j] << s ; lo = tmp1[(j + 1) % 32] >> (8 - s))
        }
    }

    // ---- Étape 2 : extraire exactement 38 bits LSB depuis les 6 octets tmp2[0..=5] ----
    // En little-endian, l'indice 0 est le poids FAIBLE (LSB), l'indice 5 le poids FORT (MSB).
    // "Garder les 38 premiers bits" dans ce contexte = garder les 38 bits de POIDS FAIBLE
    // du bloc de 6 octets tmp2[0..=5] (soit b0..b3 entiers + 6 bits faibles de b4 ; b5 est ignoré).
    let b = &tmp2[..6];                        // b[0]..b[5] : les 6 premiers octets après rotation

    let mut value38: u64 = 0;                  // valeur de sortie sur 38 bits (stockée dans un u64)
    let mut factor: u64 = 1;                   // facteur little-endian courant : 256^0, puis 256^1, ...

    // 2a) Ajouter b0..b3 en entier : 4 × 8 = 32 bits
    for i in 0..4 {
        value38 += (b[i] as u64) * factor;     // b[i] pèse 256^i (LE)
        factor *= 256;                         // passage au poids suivant (×256)
    }

    // 2b) Ajouter uniquement les 6 bits FAIBLES de b4 : 32 + 6 = 38 bits au total
    let low6 = (b[4] as u64) % 64;             // garde les 6 LSB de b4 (2^6 = 64)
    value38 += low6 * factor;                  // factor vaut ici 256^4

    // (Les 2 bits FORTS de b4 et tout b5 (8 bits) sont ignorés → 10 bits MSB supprimés)

    // Optionnel (débogage) : vérifier qu'on est bien borné à 38 bits.
    // debug_assert!(value38 < 2u64.pow(38));

    value38                                     // retourne un u64 dont seuls les 38 LSB sont utilisés
}



/* @Student
 * Write necessary code here,  or create other files.
 */

/// Basic Hellman TMTO Table construction aimed to cover a 38-bits unsigned integer probability
/// space against a SHA256 hashing function.
/// Reduction functions are supposed to be a right rotation of N bits such that there are at most
/// 255 admissible reduction functions.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of tables to generate, limited to 255 tables.
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=255))]
    ntables: u8,
    /// Number of chains.
    nchains: u64,
    /// Number of columns excluding the endpoints.
    ncolumns: u64,
    /// Path to directory storing table(s)
    #[arg(default_value=default_table_path().into_os_string())]
    path: PathBuf,
}


fn default_table_path() -> PathBuf {
    let mut path = env::current_dir().expect("Could not access current directory. Are rights correctly set?");
    path.push("tables");
    path
}


fn main() {
    let args = Args::parse();

    // S'assurer que le dossier de sortie existe
    if !args.path.exists() {
        fs::create_dir_all(&args.path).expect("Impossible de créer le dossier de sortie");
    }

    // Étape 1 : Génération des mots de passe initiaux (38 bits)
    let entries = generated_aleatoire_passwords(args.nchains);
    let mut handles = vec![];

    // Étape 2 : Générer chaque table dans un thread
    for i in 1..=args.ntables {
        // Capturer les valeurs nécessaires dans le thread
        let path = args.path.clone();
        let entries = entries.clone();
        let nchains = args.nchains;
        let ncolumns = args.ncolumns;
        let i = i;

        // Spawn du thread
        let handle = thread::spawn(move || {
            let mut filepath = path;
            filepath.push(format!("{}.txt", i)); // 1.txt, 2.txt, etc.

            let file = File::create(&filepath).expect("Erreur lors de la création du fichier");
            let mut writer = BufWriter::new(file);

            writeln!(writer, "nchains={}, ncolumns={}, redu={}", nchains, ncolumns, i).expect("Erreur lors de l'écriture");

            for &start in &entries {
                let mut m = start;
                let hash = Sha256::digest(&m.to_le_bytes());
                m = reduction_function(&hash.into(), i);

                for _ in 1..ncolumns {
                    let hash = Sha256::digest(&m.to_le_bytes());
                    m = reduction_function(&hash.into(), i);
                }

                writeln!(writer, "{} {}", start, m).expect("Erreur lors de l'écriture");
            }
        });

        // On sauvegarde le handle pour plus tard
        handles.push(handle);
    }

    // Attendre que tous les threads se terminent — EN DEHORS de la boucle
    for handle in handles {
        handle.join().unwrap();
    }
}