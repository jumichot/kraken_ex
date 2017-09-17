defmodule KrakenEx.OHLC do
  @moduledoc  """
  This module gets OHLC data from Kraken's public API.
  """

  @doc """
  Gets OHLC data based on:
    pair: asset pair
    interval: Interval time frame interval in minutes (optional):
	           1 (default), 5, 15, 30, 60, 240, 1440, 10080, 21600
    since: return committed OHLC data since given id (optional.  exclusive)

  returns
    Success: `{:ok, ohlc_data}`.
    Fail:    `{:error, errors}`

  # Examples

    iex> KrakenEx.ohlc(pair: "XXLMXXBT")
    iex> KrakenEx.ohlc(pair: "XXLMXXBT", interval: 5, since: 121343244)
    iex> KrakenEx.ohlc(pair: "XXLMXXBT", interval: 5)
    iex> KrakenEx.ohlc(pair: "XXLMXXBT", since: 121343244)
    %{"XXLMXXBT" => [[1497873720, "0.00001523", "0.00001523", "0.00001523",
      "0.00001523", "0.00000000", "0.00000000", 0],
      ...
      [1497877020, "0.00001517", ...], [1497877080, ...], [...], ...]]
      "last" => 1497916800}}

  # More info
   You can find more info on Kraken's own [documentation](https://www.kraken.com/help/api#get-ohlc-data).
  """

  alias KrakenEx.{
    PublicClient,
    PairRequiredParamError
  }

  @method "OHLC"

  def ohlc(pair, opts \\ []) do
    @method
    |> compose_url(pair[:pair], pair[:interval], pair[:since])
    |> PublicClient.get
    |> parse_response
  end

  defp compose_url(method, nil, _, _), do: raise PairRequiredParamError
  defp compose_url(method, pair, nil, nil), do: "#{method}?pair=#{pair}"
  defp compose_url(method, pair, interval, nil), do: "#{method}?pair=#{pair}&interval=#{interval}"
  defp compose_url(method, pair, nil, since), do: "#{method}?pair=#{pair}&since=#{since}"
  defp compose_url(method, pair, interval, since) do
    "#{method}?pair=#{pair}&intreval=#{interval}&since=#{since}"
  end

  defp parse_response({:ok, response}), do: parse_body(response.body)
  defp parse_response(other_response), do: other_response

  defp parse_body(%{"error" => [], "result" => result}), do: {:ok, result}
  defp parse_body(%{"error" => errors}) do
    {:error, errors}
  end
end
