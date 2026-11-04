# Jeu de cybersécurité « Collision MD5 »

Jeu linéaire pour la plateforme [CyberRangeCZ](https://docs.platform.cyberrange.cz/), basé sur le *MD5 Collision Attack Lab* de SEED Labs. Organisation inspirée du dépôt `cyberrangecz/library-junior-hacker`.

## Résumé des niveaux

- lire l'introduction et se connecter à la machine `lab`
- **Tâche 1** : générer deux fichiers différents de même hash MD5 avec `md5collgen`
- **Questions 1 et 2** : comprendre le padding (préfixe de 36 puis de 64 octets)
- **Tâche 2** : vérifier que la collision survit à l'ajout d'un suffixe commun (`cat`)
- **Tâche 3** : produire deux exécutables de même hash et de sorties différentes (`head`, `tail`, `grep`)
- **Tâche 4** : scénario du certificat, programme bénin et programme malicieux de même hash
- conclusion

## Topologie

| Hôte   | Image               | Flavor         |
| ------ | ------------------- | -------------- |
| lab    | ubuntu-focal-x86_64 | standard.small |
| router | debian-12-x86_64    | standard.small |

## Contenu du dépôt

- `game_design.md` : conception pédagogique, énoncés, indices et solutions
- `training.json` : définition d'entraînement (niveaux, flags, indices, pénalités)
- `topology.yml` : machines et réseau
- `provisioning/` : playbook Ansible, fichiers de départ (`prefix.txt`, `suffix.txt`, `prog.c`, `prog4.c`) et scripts `check_task1..4` qui valident le travail et affichent le flag

## Points à adapter

- Les noms d'images dans `topology.yml` doivent correspondre à ceux de votre plateforme.
- Le playbook compile `md5collgen` depuis `hashclash` (accès réseau requis). Hors ligne, déposez un binaire `md5collgen` et remplacez ces tâches par une copie.
- Les flags sont statiques et lisibles dans `/usr/local/bin/check_task*` : suffisant pour un TP, à durcir pour un usage en compétition.
- Le format exact de `training.json` et `topology.yml` doit être vérifié par un import test, puis comparé à un export de votre plateforme.

## Licence

Code (playbook, scripts, JSON/YAML) : MIT. Conception du jeu : CC BY-NC-SA 4.0, car dérivée du SEED Lab (voir `ATTRIBUTION.txt`).
