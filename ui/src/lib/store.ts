import * as React from "react"

/**
 * A value that lives outside React, such as the worksheets (which keep running while other pages
 * show) or the polled query history. State is replaced, never mutated, so components re-render
 * only when what they select changes.
 */
export type Store<T> = {
  get: () => T
  set: (next: T | ((current: T) => T)) => void
  subscribe: (listener: () => void) => () => void
}

export function createStore<T>(initial: T): Store<T> {
  let state = initial
  const listeners = new Set<() => void>()
  return {
    get: () => state,
    set(next) {
      const value =
        typeof next === "function" ? (next as (current: T) => T)(state) : next
      if (Object.is(value, state)) return
      state = value
      for (const listener of listeners) listener()
    },
    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
  }
}

/** Part of a store's state. `select` must return something already in the state. */
export function useStore<T, S = T>(
  store: Store<T>,
  select: (state: T) => S = (state) => state as unknown as S
): S {
  return React.useSyncExternalStore(store.subscribe, () => select(store.get()))
}
