/*
 ------------------------------------------------------------------------------
 Nom du fichier : mythread.h
 Auteur(s)      : Alexandre Shyshmarov Theo Pilet
 Date creation  : 17.10.2023

 Description    : Definition de la fonction passwordCrack

 Remarque(s)    :
 ------------------------------------------------------------------------------
*/

#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <pcosynchro/pcothread.h>
#include <QString>
#include <QVector>
#include "threadmanager.h"

/*
 * Les paramètres sont les suivants:
 *
 * - hash:      le hash dont on doit retrouver la préimage
 * - salt:      le sel à concaténer au début du mot de passe avant de le hasher
 * - charset:   QString contenant tous les caractères possibles du mot de passe
 * - nbToCompute:   Nombre maximal de mot de passe possible
 * - threadManager: reference sur le thread manager appelant
 * - currentPasswordArray: mot de passe à partir du quel commencer
 * - nbChars:   le nombre de caractères du mot de passe à bruteforcer
 * - password:  le mot de passe trouvé. "" si rien trouvé
 *
 * Cette fonction doit retourner le mot de passe correspondant au hash, ou une
 * chaine vide si non trouvé.
 */
void passwordCrack(
        const QString& hash,
        const QString& salt,
        const QString& charset,
        long long unsigned nbToCompute,
        ThreadManager* threadManager,
        QVector<unsigned int> currentPasswordArray,
        unsigned int nbChars,
        QString* password
        );

#endif // MYTHREAD_H
