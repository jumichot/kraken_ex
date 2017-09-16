defmodule KrakenEx.Authentication do
  use Bitwise
  @api_version (Application.get_env(:kraken_ex, :api_version, System.get_env("API_VERSION")) || "0")

  @base_path "/" <> @api_version <> "/private/"

  def generate_signature(method, params) do
    key = Base.decode64!(KrakenEx.private_key)
    nonce = generate_nonce()
    body = Map.merge(%{nonce: nonce}, params) |> URI.encode_query
    method = @base_path <> method

    message = generate_message(nonce, body, method)

    signature = :crypto.hmac(:sha512, key, message)
      |> Base.encode64

    {body, signature}
  end

  defp generate_message(nonce, body, method) do
    digest = :crypto.hash(:sha256, nonce <> body)
    method <> digest
  end

  # Generate a 64-bit nonce where the 48 high bits come directly from the current
  # timestamp and the low 16 bits are pseudorandom. We can't use a pure [P]RNG here
  # because the Kraken API requires every request within a given session to use a
  # monotonically increasing nonce value.
  defp generate_nonce do
    Integer.to_string(:os.system_time(:milli_seconds)) <> "0"
  end
end
