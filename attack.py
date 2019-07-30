class Attack(object):
    """A collection of suspicious events, attributed to a specific user"""

    def __init__(self, eventCount, dateTime):
        self.eventCount = eventCount
        self.dateTime = dateTime
