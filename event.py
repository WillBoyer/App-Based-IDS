class Event(object):
    """Suspicious activity captured by the detection point"""

    def __init__(self, dateTime, ipAddress, detectionPointId, dataInput):
        self.dateTime = dateTime
        self.ipAddress = ipAddress
        self.detectionPointId = detectionPointId # Foreign key
        self.dataInput = dataInput # User input deemed suspicious by IDS
