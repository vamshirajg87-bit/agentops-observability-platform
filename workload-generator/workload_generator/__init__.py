"""
workload_generator

Phase 14.3: Realistic workload generator for the AgentOps demo agent.

Phase 14.3B holds the planning half only: from one seed it derives an ordered
list of planned requests (who asks what, when, and what is meant to go wrong)
and reports on that plan.  Nothing is executed and nothing is sent anywhere.

Modules:
    rng         seeded, request-local draws
    personas    the four traffic profiles and their query pools
    scenarios   the scenario vocabulary and where its episodes fall
    plan        the plan data model and the planner
    report      plan metrics, text summary, JSON
    cli         command-line entry point with safety limits
"""

__version__ = "0.1.0"
