#include "mythread.h"
#include "threadmanager.h"
#include <QString>
#include <QCryptographicHash>

using namespace std;


void passwordCrack(
        const QString& hash,
        const QString& salt,
        const QString& charset,
        long long unsigned nbToCompute,
        ThreadManager* thisThread,
        QVector<unsigned int> currentPasswordArray,
        unsigned int nbChars,
        QVector<PcoThread*>& threads,
        QString* password
        ){

    QCryptographicHash md5(QCryptographicHash::Md5);
    QString currentHash;
    unsigned int i;
    long long unsigned nbComputed = 0;
    unsigned int nbValidChars = charset.length();

    QString currentPasswordString;

    // Convertis le mot de passe en String avant de commencer la recherche
    for (i=0;i<nbChars;i++)
        currentPasswordString[i]  = charset.at(currentPasswordArray.at(i));

    while (nbComputed < nbToCompute) {

        if(PcoThread::thisThread()->stopRequested()){
            return;
        }

        /* On vide les données déjà ajoutées au générateur */
        md5.reset();
        /* On préfixe le mot de passe avec le sel */
        md5.addData(salt.toLatin1());
        md5.addData(currentPasswordString.toLatin1());
        /* On calcul le hash */
        currentHash = md5.result().toHex();

        /*
         * Si on a trouvé, on retourne le mot de passe courant (sans le sel)
         */
        if (currentHash == hash){
            *password = currentPasswordString;

            // On demande l'arret aux threads. Sauf au thread qui à trouvé le mdp
            for(auto& t : threads){
                if(t != PcoThread::thisThread()){ t->requestStop(); }
            }

            return;
        }



        /*
         * Tous les 1000 hash calculés, on notifie qui veut bien entendre
         * de l'état de notre avancement (pour la barre de progression)
         */
        if ((nbComputed % 1000) == 0) {
            thisThread->incrementPercentComputed((double)1000/nbToCompute);
        }

        /*
         * On récupère le mot de pass à tester suivant.
         *
         * L'opération se résume à incrémenter currentPasswordArray comme si
         * chaque élément de ce vecteur représentait un digit d'un nombre en
         * base nbValidChars.
         *
         * Le digit de poids faible étant en position 0
         */
        i = 0;

        while (i < (unsigned int)currentPasswordArray.size()) {
            currentPasswordArray[i]++;

            if (currentPasswordArray[i] >= nbValidChars) {
                currentPasswordArray[i] = 0;
                i++;
            } else
                break;
        }

        /*
         * On traduit les index présents dans currentPasswordArray en
         * caractères
         */
        for (i=0;i<nbChars;i++)
            currentPasswordString[i]  = charset.at(currentPasswordArray.at(i));

        nbComputed++;
    }
}

