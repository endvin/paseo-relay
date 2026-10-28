defmodule PaseoRelay.RouteInfo do
  @moduledoc false
  @behaviour :cowboy_handler
  @impl true
  def init(request, _) do
    headers = %{
      "content-type" => "application/json",
      "cache-control" => "no-store",
      "access-control-allow-origin" => "*",
      "access-control-allow-methods" => "GET, OPTIONS",
      "access-control-allow-headers" => "x-relay-route-token"
    }

    {status, body} =
      case :cowboy_req.method(request) do
        "OPTIONS" ->
          {204, ""}

        "GET" ->
          case PaseoRelay.RouteObservations.lookup(
                 :cowboy_req.header("x-relay-route-token", request, "")
               ) do
            nil -> {404, ~s({"error":"route unavailable"})}
            route -> {200, Jason.encode!(route)}
          end

        _ ->
          {405, ~s({"error":"method not allowed"})}
      end

    {:ok, :cowboy_req.reply(status, headers, body, request), nil}
  end
end
