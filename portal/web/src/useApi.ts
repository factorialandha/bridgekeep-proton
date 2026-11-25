import { useCallback, useEffect, useState } from "react"
import { api, ApiError } from "./api"

export function useApi<T>(path: string) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const load = useCallback(() => {
    api.get<T>(path).then(setData, (e) => setError(e instanceof ApiError ? e : new ApiError(0, "The portal didn't answer.")))
  }, [path])
  useEffect(load, [load])
  return { data, error, reload: load }
}
