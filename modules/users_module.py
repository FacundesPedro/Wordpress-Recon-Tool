# recon_wp/modules/users_module.py
"""
Users module - user enumeration.

Discovers WordPress user accounts through various endpoints.
"""

# WHAT: Enumerates user accounts via REST API, oEmbed, author IDs, login errors
# HOW: Queries user-disclosing endpoints and analyzes responses
# WHY: User enumeration aids targeted brute force and social engineering
# STEPS: AuthorIdStep, RestApiUsersStep, OembedUsersStep, LoginVerbosityStep

from modules.module import Module
from steps.users import (
    AuthorIdStep,
    LoginVerbosityStep,
    OembedUsersStep,
    RegistrationStep,
    RestApiUsersStep,
)


class UsersModule(Module):
    name = "users"
    description = "User enumeration (REST API, oembed, author ID, login verbosity, registration)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(AuthorIdStep)
        self.add_step(RestApiUsersStep)
        self.add_step(OembedUsersStep)
        self.add_step(LoginVerbosityStep)
        self.add_step(RegistrationStep)
