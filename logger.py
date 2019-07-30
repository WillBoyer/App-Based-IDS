import argparse
from datetime import datetime
from event import Event
import event_analysis as analysis
import os.path
import sqlite3

# The argparse module collects the command-line input from the detection points
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ip_address', required=True)
parser.add_argument('-e', '--detection_point', required=True)
parser.add_argument('-n', '--input', required=False)
args = parser.parse_args()
date_time = datetime.now()

# Collate all relevant info into an object, to pass to logEvent()
event = Event(date_time, args.ip_address, args.detection_point, args.input)

# # INSECURE VERSION: Susceptible to the same SQL injection attack it's supposed
# # to detect.
# # Constructs the new entry for the Event Log, and writes it to the file.
# def logEvent(event):
#     conn = sqlite3.connect('../IDS/newLog.db')
#     cursor = conn.cursor()
#     with conn:
#         cursor.execute("""INSERT INTO events(date_time, ip_address, detection_point_id, data_input)
#                           VALUES ('{}', '{}', '{}', '{}')""".format(event.dateTime, event.ipAddress, event.detectionPointId, event.dataInput))


# SECURE VERSION
# Constructs the new entry for the Event Log, and writes it to the file.
def logEvent(event):
    conn = sqlite3.connect('../IDS/newLog.db')
    cursor = conn.cursor()
    with conn:
        cursor.execute("""INSERT INTO events(date_time, ip_address, detection_point_id, data_input)
                          VALUES (?, ?, ?, ?)""", (event.dateTime, event.ipAddress, event.detectionPointId, event.dataInput))

# Since the ID of the newly-recorded entry is automatically set by the DB,
# the Python script must obtain the ID after recording the new entry.
def getNewEventId():
    conn = sqlite3.connect('../IDS/newLog.db')
    cursor = conn.cursor()
    with conn:
        cursor.execute("""SELECT * FROM events WHERE date_time = (SELECT MAX (date_time) FROM events)""")
        newEventId = cursor.fetchone()[0]
    return newEventId

logEvent(event)
new_event_id = getNewEventId()

# Uses event analysis engine functions
categoryId = analysis.getCategoryId(event.detectionPointId)
similar_events = analysis.getSimilarEvents(event.dateTime, event.ipAddress, categoryId)
previous_attack = analysis.previousAttack(new_event_id, similar_events)
new_attack, eventCount = analysis.newAttack(previous_attack, similar_events, categoryId)

if new_attack == True:
    analysis.logAttack(eventCount, similar_events, categoryId)
