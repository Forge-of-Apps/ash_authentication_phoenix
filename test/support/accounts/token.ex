# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.Accounts.Token do
  @moduledoc false
  use Ash.Resource,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication.TokenResource],
    domain: Example.Accounts,
    simple_notifiers: [AshAuthentication.Phoenix.TokenRevocationNotifier]

  token do
    endpoints [AshAuthentication.Phoenix.Test.Endpoint]
    live_socket_id_template &"users_sessions:#{&1["jti"]}"
  end

  actions do
    defaults [:read]
  end
end
