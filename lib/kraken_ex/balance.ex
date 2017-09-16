defmodule KrakenEx.Balance do

  alias KrakenEx.{Headers, PrivateClient, Authentication}

  @method "Balance"

  def balance do
    {body, signature} = Authentication.generate_signature(@method, %{})
    headers = Headers.header(signature)
    PrivateClient.post(@method, body, headers, [recv_timeout: 5000])
    |> parse_response
  end

  defp parse_response({:ok, response}), do: parse_body(response.body)
  defp parse_response(other_response), do: other_response
  defp parse_body(%{"error" => [], "result" => result}) do
    {:ok, result}
  end

  defp parse_body(%{"error" => errors}) do
    {:error, errors}
  end
end
