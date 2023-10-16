#include <QCryptographicHash>
#include <QVector>

#include "threadmanager.h"
#include "mythread.h"
#include <pcosynchro/pcothread.h>
#include <QDebug>
#include <cmath>

QVector<PcoThread*> threads;


/*
 * std::pow pour les long long unsigned int
 */
long long unsigned int intPow (
        long long unsigned int number,
        long long unsigned int index)
{
    long long unsigned int i;

    if (index == 0)
        return 1;

    long long unsigned int num = number;

    for (i = 1; i < index; i++)
        number *= num;

    return number;
}

ThreadManager::ThreadManager(QObject *parent) :
    QObject(parent)
{}


void ThreadManager::incrementPercentComputed(double percentComputed)
{
    emit sig_incrementPercentComputed(percentComputed);
}


/*
 * Les paramètres sont les suivants:
 *
 * - charset:   QString contenant tous les caractères possibles du mot de passe
 * - salt:      le sel à concaténer au début du mot de passe avant de le hasher
 * - hash:      le hash dont on doit retrouver la préimage
 * - nbChars:   le nombre de caractères du mot de passe à bruteforcer
 * - nbThreads: le nombre de threads à lancer
 *
 * Cette fonction doit retourner le mot de passe correspondant au hash, ou une
 * chaine vide si non trouvé.
 */
QString ThreadManager::startHacking(
        QString charset,
        QString salt,
        QString hash,
        unsigned int nbChars,
        unsigned int nbThreads
)
{

    /*
     * Mot de passe à tester courant
     */
    QString currentPasswordString = "";

    long long unsigned int nbToCompute = intPow(charset.length(),nbChars);

    /*
     * Vecteur contenant les differents mot de passe pour chaque thread
     */
    QVector<QVector<unsigned int>> VecCurrentPasswordArray(nbThreads);

    // Calcule à quel caractère doit commencer chaque thread
    unsigned int interval = floor(charset.length() / nbThreads);
    unsigned int startChar = 0;

    /*
     * Boucle remplissant chaque vecteur de mot de passe.
     * Le dernier caractere est celui qui determine à partir d'ou le thread commence à chercher
     */
    for(auto it = VecCurrentPasswordArray.begin(); it != VecCurrentPasswordArray.end(); ++it , startChar += interval){
        it->fill(0,nbChars);
        it->back() = startChar;
    }


    for(unsigned int i = 0 ; i < nbThreads; ++i){
        threads.push_back(new PcoThread(passwordCrack,
                                        hash,
                                        salt,
                                        charset,
                                        nbToCompute,
                                        this,
                                        VecCurrentPasswordArray[i],
                                        nbChars,
                                        std::ref(threads),
                                        &currentPasswordString));
    }

    for (auto& t : threads) {
        t->join();
        delete t;
    }

    return currentPasswordString;
}
