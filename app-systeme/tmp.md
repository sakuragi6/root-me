# L’épopée Root-Me : App-Système | ELF x86 - Stack buffer overflow basic 2

## 1. Informations Générales & Configuration de l'Environnement

| Protection | Nom complet | État |
| :--- | :--- | :---: |
| **PIE** | Position Independent Executable | [❌] |
| **RelRO** | Read Only relocations | [❌] |
| **NX** | Pile non exécutable | [✔️] |
| **Heap exec** | Tas non exécutable | [✔️] |
| **ASLR** | Distribution aléatoire de l'espace d'adressage | [❌] |
| **SF** | Source Fortification | [❌] |
| **SSP** | Stack-Smashing Protection | [❌] |
| **SRC** | Accès au code source | [✔️] |

---

## 2. Analyse du Code Source

```[langage]
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/types.h>
    #include <unistd.h>
     
    void shell() {
        setreuid(geteuid(), geteuid());
        system("/bin/bash");
    }
     
    void sup() {
        printf("Hey dude ! Waaaaazzaaaaaaaa ?!\n");
    }
     
    void main()
    {
        int var;
        void (*func)()=sup;
        char buf[128];
        fgets(buf,133,stdin);
        func();
    }
```

### Le challenge :

La première étape de ce challenge va être la lecture du code. Voici les informations notables :

- [Information notable 1 : allocations, tailles des buffers, types de données...]
- [Information notable 2 : fonctions utilisées, entrées utilisateur...]
- [Information notable 3 : restrictions, filtres ou caractères interdits...]

Une première faille semble me sauter aux yeux : [Description synthétique de la vulnérabilité observée].

---

## 3. Exploitation & Démarche de Résolution

### Étape 1 : Déroulement basique du script

Tout d'abord, on va vérifier le déroulement basique du programme :

```bash
# Exemple d'interaction et de tests initiaux
```

On voit plusieurs cas de figures :
- [Cas 1 : comportement normal lors d'une saisie standard]
- [Cas 2 : réaction du binaire face aux filtres ou entrées spécifiques]
- [Cas 3 : comportement lors d'une saisie trop longue ou anormale (Crash / Segfault)]

### Étape 2 : Identification de la vulnérabilité

[Explication des essais effectués pour tester et isoler la vulnérabilité]

```bash
# Commandes et tests de payload
```

[Analyse du résultat obtenu]

### Étape 3 : Analyse du comportement

[Explication technique détaillée du mécanisme sous-jacent (mémoire, registres, tas, pile, bypass de filtres...)]

### Étape 4 : Exploitation

Maintenant que nous avons trouvé une solution, nous allons essayer de [Objectif : exécuter la commande / obtenir le shell / lire le fichier].

```bash
# Commande finale d'exploitation et obtention du flag
```

Le mot de passe est en poche.

---

## 4. Comment se protéger ?

Ici, l'erreur venait de [Description de la faille dans le code source d'origine].

Pour corriger ce problème, la solution est :

1. [Recommandation de sécurité / correctif 1]
2. [Recommandation de sécurité / correctif 2]
