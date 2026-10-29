# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

Mimic.copy(Ash.Resource.Info)
Mimic.copy(AshAuthentication.TokenResource.Info)

ExUnit.start()

{:ok, _} = Phoenix.PubSub.Supervisor.start_link(name: Example.PubSub)
AshAuthentication.Phoenix.Test.Endpoint.start_link()
