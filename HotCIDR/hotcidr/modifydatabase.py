import MySQLdb
import datetime
import time
import sys

class Database:

    host = 'localhost'
    user = 'root'
    password = ''
    db = 'AWS_AuditingDB'

    def __init__(self):
        try:
            self.connection = MySQLdb.connect(self.host, self.user, self.password, self.db)
        except:
            print('ERROR: No mysql database found.')
            sys.exit(1)

        self.cursor = self.connection.cursor()

    def insert(self, query, queryParams):
            self.cursor.execute(query, queryParams)
            self.connection.commit()

    def query(self, query):
        cursor = self.connection.cursor( MySQLdb.cursors.DictCursor )
        cursor.execute(query)
        return cursor.fetchall()

    def queryDel(self, query):
         self.cursor.execute(query)
         self.connection.commit()

    def __del__(self):
        self.connection.close()

def clearDatabase():    
    db = Database()

    deleteADD = "DELETE FROM ADDED_RULES;" 
    db.queryDel(deleteADD)
 
    deleteDEL = "DELETE FROM DELETED_RULES;" 
    db.queryDel(deleteDEL)

def printSinceSpecifiedTime(fromTime, toTime):

    db = Database()


    returnDict = {}
    returnDict['addedDict'] = {}
    returnDict['deletedDict'] = {}

    select_queryA = "SELECT * FROM ADDED_RULES" # WHERE 'secondsAgo' BETWEEN  %s AND %s" % (fromTime, toTime)

    dataAdd = db.query(select_queryA)

    for elemA in dataAdd:
        if elemA['secondsAgo'] < fromTime and elemA['secondsAgo'] > toTime:
           if str(elemA['modifiedGroup']) in returnDict['addedDict'].keys():
              returnDict['addedDict'][str(elemA['modifiedGroup'])].append(elemA)
           else:
              returnDict['addedDict'][str(elemA['modifiedGroup'])] = []
              returnDict['addedDict'][str(elemA['modifiedGroup'])].append(elemA)


    select_queryD = "SELECT * FROM DELETED_RULES" # WHERE 'secondsAgo' BETWEEN  %s AND %s" % (fromTime, toTime)

    dataDel = db.query(select_queryD)

    for elemD in dataDel:
        if elemD['secondsAgo'] < fromTime and elemD['secondsAgo'] > toTime:
           if str(elemD['modifiedGroup']) in returnDict['deletedDict'].keys():
              returnDict['deletedDict'][str(elemD['modifiedGroup'])].append(elemD)
           else:
              returnDict['deletedDict'][str(elemD['modifiedGroup'])] = []
              returnDict['deletedDict'][str(elemD['modifiedGroup'])].append(elemD)

    return returnDict



def modifyTable(dictEntry):

    db = Database()

    if dictEntry['added_or_revoked'] == 1:
       table = 'ADDED_RULES'
    else:
       table = 'DELETED_RULES'

    current = datetime.datetime.now()
    currStr = str(current).rstrip('datetime.datetime')
    finalStr = str(currStr[:19])
    secondsAgo = time.mktime(current.timetuple())



    dictEntry['time_and_date'] = finalStr
    dictEntry['secondsAgo'] = secondsAgo

    query = ("INSERT INTO " + table +
            "(`modifiedGroup`, `description`, `direction`, `protocol`, `location`, `toport`, `fromport`, `justification`, `time_and_date`, `secondsAgo`)"
            "VALUES(%s,%s,%s,%s,%s,%s,%s,%s, %s, %s)")


    queryParams = (dictEntry['modifiedGroup'], dictEntry['description'], dictEntry['direction'], dictEntry['protocol'], dictEntry['location'],dictEntry['toport'], dictEntry['fromport'], dictEntry['justification'], dictEntry['time_and_date'], dictEntry['secondsAgo'])


    db.insert(query, (queryParams))
