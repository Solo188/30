package org.littleshoot.proxy.mitm;

/**
 * Simple stopwatch used to log certificate generation time.
 */
public class MillisecondsDuration {

    private final long start = System.currentTimeMillis();

    @Override
    public String toString() {
        return String.valueOf(System.currentTimeMillis() - start);
    }
}
