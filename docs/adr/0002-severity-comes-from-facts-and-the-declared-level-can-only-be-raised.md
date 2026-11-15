# ADR 0002: Severity comes from facts with reasons, and the declared level can only be raised

## Status

Accepted

## Context

An incident is declared by someone under pressure, who may under-call it to avoid alarm or because they do not yet know the scale. A lower severity gives longer deadlines and fewer people, so an understatement slows the response in exactly the cases that need it fastest. A severity that comes from a gut feeling also cannot be argued with afterwards.

## Decision

Severity rules are data in the policy. Each has a level, a reason in words and conditions on a small fixed set of facts. The most severe level any rule gives wins, and the reasons of the rules that set it are shown. With no match the least severe level applies, and the output says that nothing matched. An incident is run at the more severe of the declared level and the computed level: a lower declaration never slows the plan, a higher one is allowed. Lint reports an understated declaration as high severity (`AIP014`) and an overstated one as low.

## Consequences

- People can disagree with a severity by naming the fact or the rule, not by arguing about feelings. `aip classify` answers "what if" without touching any record.
- The facts are coarse (what was exposed, the harm, whether an agent acted on its own, how many people). They order the response; they do not replace judgement about a particular incident, which can always raise the level.
- A fact entered wrongly gives the wrong severity. The tool cannot check them.
- The example rules are an illustration of the shape, not a statement of how any organisation or regulator classifies incidents.
