#include <QCryptographicHash>
#include <QVector>

#include "threadmanager.h"
#include "mythread.h"
#include <pcosynchro/pcothread.h>
#include <pcosynchro/pcomutex.h>
#include<QDebug>
#include <QMutex>
#include <QWaitCondition>

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
    //unsigned int i;

    long long unsigned int nbToCompute;
    //long long unsigned int nbComputed;

    /*
     * Nombre de caractères différents pouvant composer le mot de passe
     */
    //unsigned int nbValidChars;

    /*
     * Mot de passe à tester courant
     */
    QString currentPasswordString;

    /*
     * Tableau contenant les index dans la chaine charset des caractères de
     * currentPasswordString
     */
    QVector<unsigned int> currentPasswordArray;

    /*
     * Hash du mot de passe à tester courant
     */
    //QString currentHash;

    /*
     * Object QCryptographicHash servant à générer des md5
     */
    //QCryptographicHash md5(QCryptographicHash::Md5);

    /*
     * Calcul du nombre de hash à générer
     */
    nbToCompute        = intPow(charset.length(),nbChars);
    //nbComputed         = 0;

    /*
     * Nombre de caractères différents pouvant composer le mot de passe
     */
   // nbValidChars       = charset.length();

    /*
     * On initialise le premier mot de passe à tester courant en le remplissant
     * de nbChars fois du premier caractère de charset
     */
    currentPasswordString.fill(charset.at(0),nbChars);
    currentPasswordArray.fill(0,nbChars);


    std::vector<std::unique_ptr<PcoThread>> threadList;

    long long unsigned int iterationsPerThread = nbToCompute/ nbThreads;

    /* Crée les threads, on ajoutant leur pointeur à la liste.
       Les threads sont immédiatement lancés par le constructeur. */
    for (long long unsigned int i = 0; i < nbThreads; ++i) {
            long long unsigned int nbComputedTread = i * iterationsPerThread;
            long long unsigned int nbToComputeTread = (i == nbThreads - 1) ? nbToCompute : (i + 1) * iterationsPerThread;

            /* Génère une combinaison correspondante sous forme de tableau d'indices*/
            long long unsigned tmp = nbComputedTread;
            for (long long unsigned i = 0; i < nbChars; ++i) {
                int index = tmp % charset.length();
                currentPasswordArray[i] = index;
                tmp /= charset.length();
            }

        PcoThread *currentThread = new PcoThread(passwordCrack, hash,salt,charset,nbComputedTread,nbToComputeTread,this,currentPasswordArray,nbChars,&currentPasswordString);
        threadList.push_back(std::unique_ptr<PcoThread>(currentThread));
    }

    for (auto& t : threadList) {
        t->join();
    }




    /*
     * Si on arrive ici, cela signifie que tous les mot de passe possibles ont
     * été testés, et qu'aucun n'est la préimage de ce hash.
     */
    return currentPasswordString;
}
