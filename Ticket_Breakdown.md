# Ticket Breakdown

We are a staffing company whose primary purpose is to book Agents at Shifts posted by Facilities on our platform. We're working on a new feature which will generate reports for our client Facilities containing info on how many hours each Agent worked in a given quarter by summing up every Shift they worked. Currently, this is how the process works:

- Data is saved in the database in the Facilities, Agents, and Shifts tables
- A function `getShiftsByFacility` is called with the Facility's id, returning all Shifts worked that quarter, including some metadata about the Agent assigned to each
- A function `generateReport` is then called with the list of Shifts. It converts them into a PDF which can be submitted by the Facility for compliance.

## You've been asked to work on a ticket. It reads:

**Currently, the id of each Agent on the reports we generate is their internal database id. We'd like to add the ability for Facilities to save their own custom ids for each Agent they work with and use that id when generating reports for them.**


Based on the information given, break this ticket down into 2-5 individual tickets to perform. Provide as much detail for each ticket as you can, including acceptance criteria, time/effort estimates, and implementation details. Feel free to make informed guesses about any unknown details - you can't guess "wrong".


You will be graded on the level of detail in each ticket, the clarity of the execution plan within and between tickets, and the intelligibility of your language. You don't need to be a native English speaker, but please proof-read your work.

## Your Breakdown Here

Facilities --> Shifts --> Agents

### Ticket 1: Create column `externalId` in the `Agents` table

We need this field to store the custom id that the Facility can provide for each Agent.

* The field should be a nullable varchar(256)

### Ticket 2: Update model and endpoints

The endpoints that returns Agents' metadata should always return the `externalId` field.

The endpoints that manages Agents should always be prepared to receive the `externalId` field.

**Checklist:**

- [ ] The endpoint that allows a `Facility` to post a `Shift` should be prepared to receive `externalId` in the request body
- [ ] Ensure the `getShiftsByFacility` function is returning the `externalId` field
- [ ] Ensure the pdf generated by `generateReport` have the right Agent ids
- [ ] If the Agent has no `externalId`, then its `id` should be used instead
- [ ] Create unit tests
