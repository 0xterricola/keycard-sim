package zknox.kcsim;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

import java.io.IOException;

/**
 * Wraps the raw (already secure-channel-encrypted) APDU channel and records the time spent
 * in the card for each transmitted APDU. Host-side secure channel crypto happens above this
 * layer, so "card time" excludes it.
 */
final class TimedChannel implements CardChannel {
  private final CardChannel delegate;
  private long windowNanos;
  private int windowApdus;

  TimedChannel(CardChannel delegate) {
    this.delegate = delegate;
  }

  @Override
  public APDUResponse send(APDUCommand cmd) throws IOException {
    long t0 = System.nanoTime();
    APDUResponse r = delegate.send(cmd);
    windowNanos += System.nanoTime() - t0;
    windowApdus++;
    return r;
  }

  @Override
  public boolean isConnected() {
    return delegate.isConnected();
  }

  @Override
  public int pairingPasswordPBKDF2IterationCount() {
    return delegate.pairingPasswordPBKDF2IterationCount();
  }

  void resetWindow() {
    windowNanos = 0;
    windowApdus = 0;
  }

  long windowNanos() {
    return windowNanos;
  }

  int windowApdus() {
    return windowApdus;
  }
}
