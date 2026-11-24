# L’épopée Root-Me : App - Système | ELF x86 - Format string bug basic 2

## 1. Informations Générales & Configuration de l'Environnement

| Protection | Nom complet | État |
| :--- | :--- | :---: |
| **PIE** | Position Independent Executable | [❌] 
| **RelRO** | Read Only relocations | [❌] |
| **NX** | Pile non exécutable | [✔️] |
| **Heap exec** | Tas non exécutable | [✔️] |
| **ASLR** | Distribution aléatoire de l'espace d'adressage | [❌] |
| **SF** | Source Fortification | [❌] |
| **SSP** | Stack-Smashing Protection | [✔️] |
| **SRC** | Accès au code source | [✔️] |

---

## 2. Analyse du Code Source

```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/types.h>
    #include <unistd.h>
     
    int main( int argc, char ** argv )
     
    {
     
            int var;
            int check  = 0x04030201;
     
            char fmt[128];
     
            if (argc <2)
                    exit(0);
     
            memset( fmt, 0, sizeof(fmt) );
     
            printf( "check at 0x%x\n", &check );
            printf( "argv[1] = [%s]\n", argv[1] );
     
            snprintf( fmt, sizeof(fmt), argv[1] );
     
            if ((check != 0x04030201) && (check != 0xdeadbeef))    
                    printf ("\nYou are on the right way !\n");
     
            printf( "fmt=[%s]\n", fmt );
            printf( "check=0x%x\n", check );
     
            if (check==0xdeadbeef)
            {
                    printf("Yeah dude ! You win !\n");
                    setreuid(geteuid(), geteuid());
                    system("/bin/bash");
            }
    }
```

### Le challenge :

La première étape de ce challenge va être la lecture du code. Voici les informations notables :

- Une adresse est stockée dans check, et elle est vérifiée, si elle vaut 0xdeadbeef ça appelle une fonction qui ouvre un terminal privilégié.
- L'adresse de check, contenu dans check et le contenu de fmt est affiché.
- fmt prend 128 octets en mémoire et le contenu de argv[1] est passé dedans.

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
