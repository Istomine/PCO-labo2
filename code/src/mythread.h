#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <pcosynchro/pcothread.h>
#include <QString>
#include <QVector>
#include "threadmanager.h"

void passwordCrack(
        const QString& hash,
        const QString& salt,
        const QString& charset,
        long long unsigned nbToCompute,
        ThreadManager* thisThread,
        QVector<unsigned int> currentPasswordArray,
        unsigned int nbChars,
        const std::vector<PcoThread*>& threads,
        QString* password
        );

#endif // MYTHREAD_H
