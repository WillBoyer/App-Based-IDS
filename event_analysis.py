from attack import Attack
from datetime import datetime, timedelta
import sqlite3

# Detection points are divided up into categories, each with its own threshold
# and (potentially) different responses to take against each intrusion type.
def getCategoryId(detectionPointId):
    conn = sqlite3.connect('../IDS/newLog.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    with conn:
        # Finds the threshold the event contributes to
        cursor.execute("""SELECT c.id
                          FROM categories AS c INNER JOIN detection_points AS dp
                          ON c.id = dp.category_id
                          WHERE dp.id = ? """, (detectionPointId,))

    categoryId = cursor.fetchone()[0]
    return categoryId

# To determine what thresholds (if any) have been met, must enumerate all events
# which fit the pattern, and find the sum of all their corresponding 'weights'.
def getSimilarEvents(maxDateTime, ipAddress, categoryId):
    minDateTime = maxDateTime - timedelta(days=1)
    # Queries SQL database for events from ip_address within x time,
    # which are within the same category
    conn = sqlite3.connect('../IDS/newLog.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    with conn:
        cursor.execute("""SELECT e.*, dp.weight
                          FROM events AS e INNER JOIN detection_points AS dp
                          ON e.detection_point_id = dp.id
                          INNER JOIN categories AS c
                          ON dp.category_id = c.id
                          WHERE e.date_time <= ?
                          AND e.date_time >= ?
                          AND e.ip_address = ?
                          AND c.id = ? """, (maxDateTime, minDateTime, ipAddress, categoryId))

    selected_events = cursor.fetchall()
    return selected_events

# Checks if the new event is a continuation of a previously-logged attack.
# If so, the event is added to the list of events as part of the attack
def previousAttack(newest_event_id, selected_events):
    previousAttack = False
    for i in range(0, len(selected_events)):
        if selected_events[i][5] != None:
            previousAttack = True
            conn = sqlite3.connect('../IDS/newLog.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            with conn:
                cursor.execute("""UPDATE events
                                  SET attack_id = ?
                                  WHERE events.id = ?""", (selected_event[6], newest_event_id))
            break
    return previousAttack

# Checks if recent events indicate that a new attack is taking place, by
# comparing the total events' weight to the threshold.
def newAttack(previous_attack, selected_events, category_id):
    new_attack = False
    # Retrieves threshold paired to category
    conn = sqlite3.connect('../IDS/newLog.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Need category_id to obtain the corresponding threshold
    with conn:
        cursor.execute("""SELECT c.threshold FROM categories AS c
                          WHERE c.id = ?""", (category_id,))
        threshold = cursor.fetchone()[0]
    event_count = 0
    for i in range(0, len(selected_events)):
        # Get weight of detection point linked to event
        with conn:
            cursor.execute("""SELECT d_p.weight FROM detection_points AS d_p
                              INNER JOIN events AS e
                              ON d_p.id = e.detection_point_id
                              WHERE e.id = ?""", (selected_events[i][0],))
        weight = cursor.fetchone()[0]
        # Add weight to current total
        event_count += weight
    if event_count >= threshold:
        new_attack = True
    return new_attack, event_count

# Similar to logEvent() in logger.py; stores the data in the 'attacks' table,
# intended to be viewed via the Dashboard. Also totals
def logAttack(eventCount, selected_events, categoryId):
    dateTime = datetime.now()
    attack = Attack(eventCount, dateTime)
    conn = sqlite3.connect('../IDS/newLog.db')
    cursor = conn.cursor()

    with conn:
        cursor.execute("""INSERT INTO attacks(event_count, date_time)
                          VALUES (?, ?)""", (attack.eventCount, attack.dateTime,))
        # As with logEvent(), must find attackId auto-generated by database
        # to continue.
        cursor.execute("""SELECT *
                          FROM attacks
                          WHERE date_time = (SELECT MAX (date_time) FROM attacks)""")
        attackId = cursor.fetchone()[0]

        # Records newly-logged attack as a foreign key in junction table
        cursor.execute("""INSERT INTO attacks_categories(attack_id, category_id)
                                  VALUES (?, ?)""", (attackId, categoryId))

    # Adds attack_id foreign key to each related event
    for i in range(0, len(selected_events)):
        eventId = selected_events[i][0]        # Get weight of detection point linked to event
        with conn:
            cursor.execute("""UPDATE events
                              SET attack_id = ?
                              WHERE id = ? """, (attackId, eventId,))