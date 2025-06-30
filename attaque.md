# Guide d'attaque pour HoneyFTP

Ce document présente un scénario d'utilisation du script `attaquant.py` fourni avec le honeypot **HoneyFTP**. Le but est de simuler un attaquant pour tester les fonctionnalités de détection et de journalisation du serveur.

## 1. Préparation

1. Vérifiez que `honeypot.py` est lancé et écoute sur le port `2121` (ou celui défini dans `HONEYFTP_PORT`).
2. Assurez‑vous que les dépendances Python sont installées (`twisted`, `requests`, `pyOpenSSL`, etc.).
3. Placez‑vous dans le répertoire du dépôt contenant `attaquant.py`.

## 2. Lancement du script

```bash
python attaquant.py --host <IP_HONEYPOT> --port 2121
```

Un menu interactif apparaît avec les options numérotées **0 à 18**. Les choix les plus utiles sont :

| Option | Description |
|-------:|-------------|
|0|Envoie la séquence de *port-knocking* pour débloquer le FTPS|
|1|Connexion anonyme|
|2|`NLST` – liste les fichiers du répertoire courant|
|3|`RETR` – télécharge un fichier|
|4|`STOR` – téléverse un fichier|
|5|`CWD ../..` – tente un traversée de répertoires|
|6|`SITE EXEC` – exécute une commande shell (simulation)|
|7|`SITE BOF` – envoie un long payload pour tester un overflow|
|8|`SITE HELP` – affiche les sous-commandes disponibles|
|9|`SITE VERSION` – version du serveur|
|10|`SITE GETLOG` – récupère un journal|
|11|`RNFR`/`RNTO` – renomme un fichier|
|12|`DELE` – supprime (met en quarantaine) un fichier|
|13|`MKD`/`RMD` – crée ou supprime un répertoire|
|14|Génère un rapport de session via `SITE DEBUG`|
|15|Script de reconnaissance automatisé|
|16|Script d'attaque automatisé|
|17|Rejoue une liste de commandes depuis `replay.txt`|
|18|Quitte le client|

## 3. Scénario type

1. **Débloquer le FTPS** : choisissez `0` pour envoyer la séquence de *knocking* (`4020`, `4021`, `4022`). Le serveur se met alors à écouter sur le port configuré.
2. **Connexion anonyme** : sélectionnez `16` pour lancer le script d'attaque complet. Celui-ci se connecte avec l'utilisateur `anonymous` (mot de passe vide) afin d'effectuer plusieurs actions :
   - Liste des fichiers (`NLST`)
   - Téléversement d'un fichier factice `exploit.txt`
   - Tentative de téléchargement de `root.txt`
   - Exécution simulée d'une commande via `SITE EXEC`
   - Récupération du rapport de session
3. **Analyse du rapport** : le rapport est enregistré localement dans `session_report.txt`. Il contient la trace des commandes exécutées et les fichiers potentiellement téléchargés ou téléversés.

## 4. Fonctionnalités simulées ou limitées

Le honeypot implémente certaines commandes de manière factice pour tromper l'attaquant :

- `SITE EXEC` et `SITE SHELL` ne lancent aucune commande réelle ; ils renvoient simplement un message.
- `SITE BOF` répond « Buffer overflow! » si le payload dépasse 1000 caractères, mais aucun dépassement mémoire n'a lieu.
- `DELE` déplace les fichiers dans un répertoire de quarantaine plutôt que de les supprimer définitivement.
- `STOR` accepte l'upload mais les fichiers sont conservés à des fins d'analyse.

Il est donc normal que certaines opérations ne semblent pas avoir d'effet réel. Le but est avant tout de générer des traces dans `honeypot.log` et `operations.log` pour observer le comportement d'un attaquant.

### Exemples de saisie

Lorsqu'une option demande des paramètres, vous pouvez utiliser les valeurs ci-dessous pour tester le comportement du honeypot :

- **3 – RETR**
  - `Fichier à RETR > honeypot.log`
  - `Local dest (~/...) > ~/honeypot.log`
- **4 – STOR**
  - `Local file to STOR > ~/test.txt`
  - `Remote name > test.txt`
- **6 – SITE EXEC**
  - `Commande shell > /bin/bash -c 'id'`
- **7 – SITE BOF**
  - `Taille payload > 2048`
- **10 – SITE GETLOG**
  - `Session ID (blank for global) > ` *(laisser vide pour obtenir tous les logs)*
- **11 – RNFR/RNTO**
  - `RNFR file > old.txt`
  - `RNTO name > new.txt`
- **12 – DELE**
  - `DELE file > sample.txt`
- **13 – MKD/RMD**
  - `MKD directory > tmpdir`
  - `RMD directory > tmpdir`

Ces commandes restent simulées : aucun vrai shell n'est exécuté et les fichiers
ne sont pas réellement supprimés.

## 5. Dépannage

- Si la connexion échoue, vérifiez que vous avez bien envoyé la séquence de *knocking* (option `0`).
- Pour tester localement, assurez‑vous que les ports passifs `60000‑60100` ne sont pas bloqués par un pare‑feu.
- Certains clients FTPS stricts peuvent refuser la connexion en raison du certificat auto‑signé.
- Les options avancées (`RNFR/RNTO`, `DELE`, `MKD/RMD`) peuvent renvoyer des erreurs si les chemins indiqués n'existent pas.

Ce guide résume le fonctionnement du script `attaquant.py` et ce qu'il permet de tester sur HoneyFTP. Utilisez‑le pour observer la journalisation du honeypot et vérifier que les alertes sont bien générées.
