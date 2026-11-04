# Conception du jeu « Collision MD5 »
Public : étudiants en sécurité informatique. Durée estimée : 1 h 30. Prérequis : ligne de commande Linux, notion de fonction de hachage.
Objectifs : expliquer l'importance de la résistance aux collisions, générer des collisions MD5, exploiter la propriété de concaténation, contourner un scénario de certificat.
Environnement : machine `lab` (Ubuntu), dossier `/home/ubuntu/tp_md5`. Chaque niveau se valide avec `check_taskN` (flag) ou par une réponse numérique.

## Niveau 0 — Bienvenue
# Collision MD5

MD5 a perdu sa **resistance aux collisions** : on sait fabriquer deux contenus differents ayant le meme hash.

Dans ce jeu, tu vas realiser les 4 taches du *MD5 Collision Attack Lab* (SEED Labs) :
1. generer deux fichiers differents avec le meme hash ;
2. verifier que la collision survit a l'ajout d'un suffixe commun ;
3. produire deux **executables** de meme hash mais aux sorties differentes ;
4. contourner un certificat : un programme *benin* et un programme *malicieux* de meme hash.

Connecte-toi a la machine `lab` (utilisateur `ubuntu`). Tes fichiers sont dans `/home/ubuntu/tp_md5`. Les outils `md5collgen`, `gcc`, `xxd` et `bless` sont installes.

Chaque niveau se valide avec un script `check_taskN` qui affiche un **flag** a saisir ici.

## Niveau 1 — Tache 1 - Deux fichiers, un seul hash
A partir de `/home/ubuntu/tp_md5/prefix.txt`, genere deux fichiers `out1.bin` et `out2.bin` avec `md5collgen`.

Verifie avec `diff` et `md5sum`, observe-les avec `bless` ou `xxd`, puis lance :

```
check_task1 out1.bin out2.bin
```

Saisis le flag affiche. Note aussi le nombre d'octets differents pour ton rapport (Question 3 du TP).

**Réponse / flag :** `FLAG{c0ll1de_m4me_pr3fixe_a7f3}`

**Indices :**
- Outil (−10 pts) : Le programme s'appelle md5collgen. Option -p pour le prefixe, -o pour les deux fichiers de sortie.
- Verification (−15 pts) : Compare les hash avec md5sum et les contenus avec diff ou cmp -l.

**Solution :**

```bash
cd ~/tp_md5
md5collgen -p prefix.txt -o out1.bin out2.bin
diff out1.bin out2.bin
md5sum out1.bin out2.bin
cmp -l out1.bin out2.bin
check_task1 out1.bin out2.bin
```

## Niveau 2 — Question 1 - Prefixe non multiple de 64
`prefix.txt` fait 36 octets. Les fichiers produits a la tache 1 font plus que `36 + 128` octets : l'outil a ajoute un **padding**.

Combien d'octets de padding ont ete ajoutes ? (reponse : un nombre)

**Réponse / flag :** `28`

**Indices :**
- Calcul (−10 pts) : Taille de out1.bin = prefixe + padding + 128 octets de collision. Utilise ls -l ou wc -c.

**Solution :**

```bash
ls -l prefix.txt out1.bin  ->  36 et 192 octets.
192 - 128 (bloc de collision) - 36 = 28 octets de padding, pour atteindre 64.
```

## Niveau 3 — Question 2 - Prefixe de exactement 64 octets
Cree un prefixe de **exactement 64 octets** :

```
head -c 64 /dev/urandom > prefix64.txt
```

Lance `md5collgen` dessus. Quelle est la taille (en octets) des fichiers de sortie ? (reponse : un nombre)

**Réponse / flag :** `192`

**Indices :**
- Verification (−10 pts) : Verifie d'abord que prefix64.txt fait bien 64 octets avec wc -c.

**Solution :**

```bash
head -c 64 /dev/urandom > prefix64.txt
md5collgen -p prefix64.txt -o out3.bin out4.bin
wc -c out3.bin  ->  192 (64 + 128, aucun padding ajoute).
```

## Niveau 4 — Tache 2 - La collision survit a un suffixe
Propriete de MD5 : si `MD5(M) = MD5(N)` alors `MD5(M || T) = MD5(N || T)`.

Ajoute le **meme** suffixe (`suffix.txt` ou le tien) a `out1.bin` et `out2.bin` pour obtenir `final1.bin` et `final2.bin`, puis lance :

```
check_task2 final1.bin final2.bin
```

**Réponse / flag :** `FLAG{suffixe_commun_meme_hash_5be2}`

**Indices :**
- Concatenation (−10 pts) : La commande cat permet de concatener des fichiers : cat A B > C.

**Solution :**

```bash
cd ~/tp_md5
cat out1.bin suffix.txt > final1.bin
cat out2.bin suffix.txt > final2.bin
md5sum final1.bin final2.bin
check_task2 final1.bin final2.bin
```

## Niveau 5 — Tache 3 - Deux executables, un seul hash
Compile `prog.c` (le tableau `xyz` contient 200 octets `0x41`). Decoupe l'executable en **prefixe (multiple de 64 octets) / 128 octets / suffixe**, genere la collision sur le prefixe, puis recolle pour obtenir `prog1` et `prog2` de meme hash MD5 mais aux sorties differentes.

Valide avec :

```
check_task3 prog1 prog2
```

**Réponse / flag :** `FLAG{deux_executables_un_hash_c91d}`

**Indices :**
- Localiser le tableau (−10 pts) : grep -obUaP 'A{200}' prog donne l'offset (en octets) du debut du tableau.
- Choisir le prefixe (−15 pts) : Prends le plus petit multiple de 64 superieur ou egal a l'offset : les 128 octets suivants restent dans le tableau.
- Decouper (−15 pts) : head -c N pour le prefixe, tail -c +M pour le suffixe (M = N + 129).

**Solution :**

```bash
cd ~/tp_md5
gcc -o prog prog.c
OFF=$(grep -obUaP 'A{200}' prog | cut -d: -f1)
PL=$(( (OFF + 63) / 64 * 64 ))
head -c $PL prog > prefix_bin
tail -c +$((PL + 129)) prog > suffix_bin
md5collgen -p prefix_bin -o coll1.bin coll2.bin
cat coll1.bin suffix_bin > prog1
cat coll2.bin suffix_bin > prog2
chmod +x prog1 prog2
md5sum prog1 prog2
check_task3 prog1 prog2
```

## Niveau 6 — Tache 4 - Programme benin et programme malicieux
`prog4.c` compare deux tableaux `X` et `Y` : s'ils sont egaux, la branche *benin* s'execute, sinon la branche *malicieuse* (simulee par un message).

Produis `prog4_benin` (X = P, Y = P) et `prog4_malicieux` (X = Q, Y = P) avec **le meme hash MD5**, puis valide :

```
check_task4 prog4_benin prog4_malicieux
```

C'est le scenario du certificat : le hash certifie pour la version benigne reste valable pour la version malicieuse.

**Réponse / flag :** `FLAG{certificat_md5_contourne_3e08}`

**Indices :**
- Une seule collision (−15 pts) : Une seule paire (P, Q) suffit : X recoit P ou Q, Y recoit toujours P.
- Deux tableaux (−15 pts) : grep -obUaP 'A{200}' prog4 renvoie deux offsets : celui de X puis celui de Y.
- Meme decalage (−20 pts) : Dans Y, remplace les 128 octets situes au meme decalage relatif que dans X (apres l'alignement sur 64).

**Solution :**

```bash
cd ~/tp_md5
gcc -o prog4 prog4.c
XO=$(grep -obUaP 'A{200}' prog4 | sed -n 1p | cut -d: -f1)
YO=$(grep -obUaP 'A{200}' prog4 | sed -n 2p | cut -d: -f1)
PL=$(( (XO + 63) / 64 * 64 ))
head -c $PL prog4 > prefix_bin
md5collgen -p prefix_bin -o coll1.bin coll2.bin
tail -c +$((PL + 129)) prog4 > suffix_bin
tail -c 128 coll1.bin > P.bin
REL=$(( YO - XO - 128 ))   # position de Y dans suffix_bin
head -c $REL suffix_bin > sb
tail -c +$((REL + 129)) suffix_bin > sa
cat sb P.bin sa > suffix_patched
cat coll1.bin suffix_patched > prog4_benin
cat coll2.bin suffix_patched > prog4_malicieux
chmod +x prog4_benin prog4_malicieux
md5sum prog4_benin prog4_malicieux
./prog4_benin; ./prog4_malicieux
check_task4 prog4_benin prog4_malicieux
```

## Niveau 7 — Conclusion
Bravo : tu as montre qu'une autorite qui certifie un programme par son hash MD5 peut etre trompee.

A retenir :
- MD5 n'est plus resistant aux collisions ;
- la propriete de concatenation permet d'inserer une collision dans un fichier reel ;
- il faut utiliser SHA-256 ou SHA-3 pour toute verification d'integrite ou de signature.
