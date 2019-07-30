# App-Based-IDS
Excerpts from my 3rd-year Dissertation Project: An Intrusion Detection System for a Web Application.

## Introduction
This repository contains excerpts of code written for my 3rd-year dissertation project. I am not permitted to upload the full project, so I have only included the parts which illustrate the intrusion detection system's (IDS) functionality effectively.

An application-based IDS is and IDS deployed on a Web Application. It is intended to identify suspicious activity by users, and analyse this activity to determine if a attack is taking place. The project is based upon the [OWASP AppSensor conceptual framework](https://www.owasp.org/index.php/OWASP_AppSensor_Project)

The Project is composed of several parts:
- Web Application
- Detection Points (found in `books_controller.rb` and `sessions_controller.rb`)
- Event Manager (`logger.py`)
- Event Analysis Engine (`event_analysis.py`)
- Event and Attack Stores (found in `newLog.db`)
- Responses

## Components
### Web Application
The Web Application upon which the IDS is based is written in Ruby, using the Rails framework. It follows the Model-View-Controller (MVC) model, and uses a SQLite database.

### Events and Detection Points
When a suspicious Event occurs, such as a multiple failed login attempts or a SQL Injection attack, this triggers a Detection Point.

The Detection Points for this IDS must be written within the controller code for the relevant part of the Rails-based Web Application. As a result, the Detection Points, like the rest of the application, are written in Ruby.

All Detection Points write the relevant information to the command line, calling the Event Manager.

### Event Manager
The Event Manager Python script uses the `argparse` module to interpret information passed to it by the Detection Point. This script records the details of the suspicious Event in the Event Store and, using the `include` command, prompts the Event Analysis Engine to take further action.

To log an Event, he Event Manager first constructs an Event object, and passes to it the information obtained from the Detection Point. The constructed class is then passed to the `logEvent()` method, and the Event is written to the database.

### Event Analysis Engine
The Event Analysis Engine is also written in Python and is used to examine the newly-logged Event in combination with the other logged Events. This is achieved through simple SQLite queries to the Event and Attack Stores.

Firstly, the Event Analysis Engine finds what category the Event falls into. Then it obtains a list of all Events from the past 24 hours which originate from the IP address, and which fall into the same category. Since certain Events may be more suspicious than others, each Detection Point and Event has a 'weight' value associated with it.

If the total weights of all similar Events meets or exceeds the Response threshold for that category, they are collectively recognised as an Attack, which is recorded in the Attack Store. Additionally, a Response is carried out against the attacker, such as blocking the IP address.

If any of the similar Events are found to already be classed as part of an Attack, the newly-logged Event is also classed as part of the Attack.

### Event and Attack Stores
The Event and Attack Stores take the form of a SQLite database.

A dashboard was planned to be implemented, but could not be completed at this time. it would have displayed the contents of the database in a more readable manner, including identified Attack, the Events comprising this Attack, and the action taken to prevent the intrusion.

### Response
If the threshold of a particular Attack category is reached, the IDS was planned to issue a Response to prevent the Attack from continuing. There may be multiple thresholds within a category, each corresponding to an increasing level of Response. At this time, however, the Response functionality has not been implemented.
