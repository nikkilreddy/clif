# How This Project Works

This document explains the current local demo in beginner-friendly language.

## What Is This Project?

CLIF (Cognitive Log Investigation Platform) is a small Security Operations
Center (SOC) system.

A SOC watches computer and application activity to find signs of attacks. In
this demo, a fake banking website called **SecureBank** creates attack events.
CLIF receives those events, checks how suspicious they are, investigates
the suspicious activity, and shows the result in a dashboard.

The main question the system tries to answer is:

> "Is this activity probably an attack, and what happened?"

## The Main Parts

### 1. SecureBank

SecureBank is the demo application. It behaves like a vulnerable banking
website and produces realistic security events when the attack script runs.

The attack script can demonstrate activities such as reconnaissance, failed
logins, injection attempts, and data access.

### 2. Vector

Vector is the event entrance.

It receives raw events from SecureBank, reads their format, cleans up the
important fields, and sends them into the event stream. This is useful because
the rest of the system receives events in a consistent format.

### 3. Redpanda

Redpanda is the message stream between services.

It temporarily holds events and distributes them to the services that need
them. This means SecureBank does not need to wait for every analysis step to
finish before it can send the next event.

You can think of Redpanda as a queue or conveyor belt for security events.

### 4. Consumer-Go

Consumer-Go reads events from Redpanda and stores them in ClickHouse.

It writes events in batches, which is faster than opening a separate database
operation for every single event.

### 5. ClickHouse

ClickHouse is the project's database for the demo.

It stores the incoming events and the results produced by the agents. The
dashboard uses this stored data to show event history, scores, investigations,
and verdicts.

### 6. Triage Agent

Triage is the first analysis step.

For every event, it:

1. Extracts useful information, such as time, network details, login status,
   URL patterns, and message characteristics.
2. Converts that information into a vector of **60 numerical features**.
3. Sends the features through the trained LightGBM model.
4. Produces a suspicion score and an action, such as discard, monitor, or
   escalate.
5. Sends suspicious events to Hunter for deeper investigation.

The model does not directly write a final verdict. Its job is to quickly sort
large numbers of events and identify which ones deserve more attention.

### 7. Hunter Agent

Hunter investigates events that Triage considers suspicious.

It looks at related events around the same activity and checks several kinds
of evidence, including detection rules, timing, entities, and relationships
between events. It then builds an investigation and an attack graph.

An attack graph is simply a visual representation of how events and entities
are connected. For example, it can help show that repeated login failures were
followed by a successful login and then unusual data access.

Hunter sends its investigation to Verifier.

### 8. Verifier Agent

Verifier is the final decision step.

It reviews Hunter's investigation and the supporting events. It produces an
analyst-friendly result containing information such as:

- Verdict: `true_positive`, `false_positive`, or `inconclusive`
- Confidence: how certain the system is
- Priority: how urgent the case is
- Evidence summary
- Timeline and narrative explaining what happened

`inconclusive` is an intentional result. It means the system does not have
strong enough evidence to make a safe yes-or-no decision.

### 9. Dashboard

The Next.js dashboard is the user interface for the demo.

It reads data from ClickHouse and provides pages for:

- Live event activity
- Agent status
- Investigations
- Attack graphs
- Final verdicts and narratives

## The Complete Workflow

The flow starts when the attack script creates an event:

```text
SecureBank
    |
    v
Vector
    |
    v
Redpanda
    |-------------------------------> Consumer-Go -> ClickHouse
    |
    v
Triage -> suspicious events -> Hunter -> Verifier
                                                   |
                                                   v
                                             ClickHouse
                                                   |
                                                   v
                                              Dashboard
```

There are two important paths after Redpanda:

- **Storage path:** Consumer-Go saves events in ClickHouse.
- **Analysis path:** Triage, Hunter, and Verifier process suspicious activity.

Both paths use ClickHouse so the dashboard can show the original events and the
analysis results together.

## What Happens During One Event?

Imagine SecureBank creates a failed login event.

1. SecureBank sends the event to Vector.
2. Vector parses the event and forwards it to Redpanda.
3. Consumer-Go stores a copy in ClickHouse.
4. Triage extracts 60 features and calculates a risk score.
5. If the score is high enough, Triage publishes a task for Hunter.
6. Hunter checks nearby events and relationships to understand the activity.
7. Hunter sends its findings to Verifier.
8. Verifier decides whether the activity is a likely attack, probably harmless,
   or not clear enough to classify.
9. The result is stored in ClickHouse.
10. The dashboard displays the event, investigation, and final result.

## Running the Demo

From the project root, start the local services:

```bash
./start_demo.sh
```

Then open:

- Dashboard: http://localhost:3001
- Live feed: http://localhost:3001/live-feed
- AI agents: http://localhost:3001/ai-agents
- Investigations: http://localhost:3001/investigations
- SecureBank: http://localhost:5001

Run the attack in another terminal:

```bash
python3 demo/securebank/attack.py --interactive
```

Use the faster unattended version when you do not need pauses between attack
phases:

```bash
python3 demo/securebank/attack.py --fast
```

## Simple Explanation of the AI Model

The Triage Agent uses a trained **LightGBM** model.

LightGBM is a machine-learning model made from many small decision trees. A
decision tree asks questions such as whether an event happened at an unusual
time or contains a suspicious pattern. Many trees work together to produce a
score.

The 60 input features are measurable properties of an event. Examples include:

- Time of day
- Severity
- Message length and entropy
- Port and protocol information
- Login success or failure
- Number of failed attempts
- URL and query patterns
- SQL injection, XSS, or path traversal indicators
- Whether the activity targets a sensitive service

The model's output is a score, not a complete explanation of an incident. The
Hunter and Verifier agents add context and produce the investigation narrative
that an analyst can read.

## Why Are There Multiple Agents?

Each agent has one focused responsibility:

- **Triage:** Quickly find events worth investigating.
- **Hunter:** Understand how suspicious events are connected.
- **Verifier:** Make a cautious final decision.

This separation makes the workflow easier to understand and lets each stage
produce a useful result for the next stage.

## Useful Terms

**Event**  
One recorded activity, such as a login attempt or HTTP request.

**Feature**  
A measurable value extracted from an event for the machine-learning model.

**Score**  
A number representing how suspicious an event appears.

**Investigation**  
The evidence and reasoning collected around suspicious activity.

**Attack graph**  
A map showing relationships between events, users, hosts, IP addresses, and
other entities.

**Verdict**  
The final classification from Verifier.

**Pipeline**  
The ordered path that data follows through the system.

## Stopping the Demo

```bash
docker compose -f docker-compose.local.yml down
```

Do not use `-v` unless you also want to remove the local database and stream
data volumes.
