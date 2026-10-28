defmodule PaseoRelay.RouteObservations do
  @moduledoc """
  Optional, bounded metadata for live v2 sockets. No payloads or daemon credentials.
  The HTTP read capability belongs to one client socket and expires with that socket.
  """
  use GenServer
  @table __MODULE__

  def start_link(_), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)
  def refresh, do: GenServer.call(__MODULE__, :refresh)

  def track(request, connection) do
    if connection.version == 2 && connection.connection_id not in [nil, ""] && enabled?() do
      {address, _port} = :cowboy_req.peer(request)
      token = request |> :cowboy_req.parse_qs() |> Map.new() |> Map.get("routeToken")

      source = %{
        peer: to_string(:inet.ntoa(address)),
        forwarded: String.slice(:cowboy_req.header("x-real-ip", request, ""), 0, 80)
      }

      key = {connection.server_id, connection.connection_id, connection.role}

      GenServer.cast(
        __MODULE__,
        {:track, self(), key, source, if(connection.role == :client, do: token)}
      )
    end

    :ok
  end

  def lookup(token) do
    with true <- valid_token?(token),
         [{_, {pid, key}}] <- :ets.lookup(@table, {:token, digest(token)}),
         true <- Process.alive?(pid),
         [{_, {^pid, client}}] <- :ets.lookup(@table, key),
         [{:config, config}] when is_map(config) <- :ets.lookup(@table, :config),
         {server, connection, :client} <- key do
      daemon =
        case :ets.lookup(@table, {server, connection, :server}) do
          [{_, {daemon_pid, source}}] ->
            if Process.alive?(daemon_pid), do: describe(source, config)

          _ ->
            nil
        end

      %{
        version: 1,
        observedAt: DateTime.to_iso8601(DateTime.utc_now()),
        relay: config["relay"],
        client: describe(client, config),
        daemon: daemon
      }
    else
      _ -> nil
    end
  rescue
    ArgumentError -> nil
  end

  @impl true
  def init(_) do
    :ets.new(@table, [:named_table, :protected, read_concurrency: true])
    reload()
    Process.send_after(self(), :refresh, 5_000)
    {:ok, %{}}
  end

  @impl true
  def handle_call(:refresh, _, state) do
    reload()
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:track, pid, key, source, token}, state) do
    ref = Process.monitor(pid)
    :ets.insert(@table, {key, {pid, source}})
    token_key = if valid_token?(token), do: {:token, digest(token)}
    if token_key, do: :ets.insert(@table, {token_key, {pid, key}})
    {:noreply, Map.put(state, ref, {pid, key, token_key})}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _, _}, state) do
    case Map.pop(state, ref) do
      {{pid, key, token_key}, rest} ->
        delete_owned(key, pid)
        if token_key, do: delete_owned(token_key, pid)
        {:noreply, rest}

      {nil, rest} ->
        {:noreply, rest}
    end
  end

  def handle_info(:refresh, state) do
    reload()
    Process.send_after(self(), :refresh, 5_000)
    {:noreply, state}
  end

  defp delete_owned(key, pid) do
    case :ets.lookup(@table, key) do
      [{_, {^pid, _}}] -> :ets.delete(@table, key)
      _ -> :ok
    end
  end

  defp reload do
    path =
      Application.get_env(
        :paseo_relay,
        :route_info_file,
        System.get_env("PASEO_RELAY_ROUTE_INFO_FILE", "")
      )

    config =
      with {:ok, stat} <- File.stat(path),
           true <- stat.size <= 65_536,
           {:ok, raw} <- File.read(path),
           {:ok, value} <- Jason.decode(raw),
           true <- valid_config?(value),
           do: value

    :ets.insert(
      @table,
      {:config,
       if(is_map(config), do: Map.update!(config, "relay", &Map.take(&1, ["id", "label"])))}
    )
  end

  defp enabled? do
    case :ets.lookup(@table, :config) do
      [{:config, config}] -> is_map(config)
      _ -> false
    end
  rescue
    ArgumentError -> false
  end

  defp valid_config?(value) when is_map(value) do
    place?(value["relay"]) && is_list(value["trustedProxies"]) &&
      length(value["trustedProxies"]) <= 32 &&
      Enum.all?(value["trustedProxies"], &ip?/1) && is_list(value["ingresses"]) &&
      length(value["ingresses"]) <= 32 &&
      Enum.all?(value["ingresses"], fn entry ->
        is_map(entry) && ip?(entry["address"]) && place?(entry) &&
          entry["path"] in ["private", "public-fallback", "direct"]
      end)
  end

  defp valid_config?(_), do: false

  defp describe(source, config) do
    address = if source.peer in config["trustedProxies"], do: source.forwarded, else: source.peer
    ingress = Enum.find(config["ingresses"], &(&1["address"] == address))

    cond do
      not ip?(address) ->
        %{ingress: config["relay"], path: "unknown", uplink: nil}

      ingress ->
        %{
          ingress: Map.take(ingress, ["id", "label"]),
          path: ingress["path"],
          uplink: if(ingress["path"] == "private", do: fresh_uplink(config["uplink"]))
        }

      true ->
        %{ingress: config["relay"], path: "direct", uplink: nil}
    end
  end

  defp fresh_uplink(value) when is_map(value) do
    now = DateTime.utc_now()

    with true <- place?(value),
         true <- is_boolean(value["fallback"]),
         true <- is_binary(value["observedAt"]),
         true <- is_binary(value["expiresAt"]),
         {:ok, observed, _} <- DateTime.from_iso8601(value["observedAt"] || ""),
         {:ok, expires, _} <- DateTime.from_iso8601(value["expiresAt"] || ""),
         true <- DateTime.diff(observed, now) <= 60,
         true <- DateTime.compare(expires, now) == :gt,
         true <- DateTime.diff(expires, observed) in 1..180 do
      Map.take(value, ["id", "label", "fallback", "observedAt", "expiresAt"])
    else
      _ -> nil
    end
  end

  defp fresh_uplink(_), do: nil
  defp place?(value) when is_map(value), do: label?(value["id"]) && label?(value["label"])
  defp place?(_), do: false

  defp label?(value),
    do:
      is_binary(value) && byte_size(value) in 1..240 && String.length(value) <= 80 &&
        not Regex.match?(~r/[\x00-\x1f\x7f]/, value)

  defp ip?(value) when is_binary(value),
    do: match?({:ok, _}, :inet.parse_address(String.to_charlist(value)))

  defp ip?(_), do: false

  defp valid_token?(token),
    do:
      is_binary(token) && byte_size(token) in 32..128 &&
        Regex.match?(~r/\A[a-zA-Z0-9_-]+\z/, token)

  defp digest(token), do: :crypto.hash(:sha256, token)
end
