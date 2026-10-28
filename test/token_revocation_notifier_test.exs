# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.TokenRevocationNotifierTest do
  @moduledoc false
  use AshAuthentication.Phoenix.Test.ConnCase

  alias AshAuthentication.{Jwt, TokenResource}
  alias AshAuthentication.Phoenix.Controller
  alias Example.Accounts.Token

  test "sign-in and revocation use the same live socket id", %{conn: conn} do
    {:ok, token, %{"jti" => jti}} = Jwt.token_for_user(create_user!())

    live_socket_id =
      conn
      |> Plug.Test.init_test_session(%{})
      |> put_private(:phoenix_endpoint, @endpoint)
      |> Controller.set_live_socket_id(token)
      |> get_session(:live_socket_id)

    assert live_socket_id == "users_sessions:#{jti}"

    @endpoint.subscribe(live_socket_id)

    :ok = TokenResource.Actions.revoke(Token, token)
    assert_receive %Phoenix.Socket.Broadcast{topic: ^live_socket_id, event: "disconnect"}
  end

  defp create_user! do
    strategy = AshAuthentication.Info.strategy!(Example.Accounts.User, :password)

    Example.Accounts.User
    |> Ash.Changeset.for_create(:register_with_password, %{
      strategy.identity_field => "notifier-#{System.unique_integer([:positive])}@email",
      strategy.password_field => "notifier.secret",
      strategy.password_confirmation_field => "notifier.secret"
    })
    |> Ash.create!()
  end
end
