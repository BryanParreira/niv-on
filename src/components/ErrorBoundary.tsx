import { Component, type ReactNode } from "react";
import { Icon } from "./Icon";

/** Keeps one broken page from blanking the whole app; offers a retry. */
export class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error("page crashed:", error);
  }

  componentDidUpdate(prev: { resetKey?: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="card">
        <div className="banner error">
          <Icon name="octagon" />
          <div className="grow">
            <b>This page hit an error and was stopped.</b> The rest of Niv.ON keeps running — capture and detection are unaffected.
            <div className="mono small" style={{ marginTop: 6 }}>{this.state.error.message}</div>
          </div>
          <button className="btn sm" onClick={() => this.setState({ error: null })}>Try again</button>
        </div>
      </div>
    );
  }
}
