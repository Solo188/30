package com.adblocker.vpn

import java.nio.ByteBuffer

object DnsPacketParser {

    fun extractDomain(udpPayload: ByteArray): String? {
        return try {
            if (udpPayload.size < 12) return null

            val buffer = ByteBuffer.wrap(udpPayload)

            /* transaction id */ buffer.short
            val flags  = buffer.short.toInt() and 0xFFFF
            val isQuery = (flags and 0x8000) == 0
            if (!isQuery) return null

            val qdCount = buffer.short.toInt() and 0xFFFF
            if (qdCount == 0) return null

            /* anCount, nsCount, arCount */ buffer.short; buffer.short; buffer.short

            val domainBuilder = StringBuilder()
            while (buffer.hasRemaining()) {
                val labelLen = buffer.get().toInt() and 0xFF
                if (labelLen == 0) break
                if (labelLen and 0xC0 == 0xC0) { buffer.get(); break }
                if (buffer.remaining() < labelLen) return null
                if (domainBuilder.isNotEmpty()) domainBuilder.append('.')
                val labelBytes = ByteArray(labelLen)
                buffer.get(labelBytes)
                domainBuilder.append(String(labelBytes, Charsets.US_ASCII))
            }

            if (domainBuilder.isEmpty()) null else domainBuilder.toString()
        } catch (_: Exception) { null }
    }

    /**
     * Builds a DNS NXDOMAIN/0.0.0.0 block response for the given query.
     * Returns the original query bytes if parsing fails (safe fallback).
     * Fix #10: removed dead code — previous version built an unused ByteArray before fullResponse.
     */
    fun buildBlockedResponse(originalDnsQuery: ByteArray): ByteArray {
        if (originalDnsQuery.size < 12) return originalDnsQuery

        val queryEnd = findQueryEnd(originalDnsQuery)
        if (queryEnd < 0) return originalDnsQuery

        val fullResponse = ByteArray(queryEnd + 16)
        System.arraycopy(originalDnsQuery, 0, fullResponse, 0, queryEnd)

        val buf = ByteBuffer.wrap(fullResponse)
        // flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=0
        buf.position(2); buf.putShort(0x8180.toShort())
        // QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
        buf.position(4)
        buf.putShort(1); buf.putShort(1); buf.putShort(0); buf.putShort(0)

        // Answer: pointer to question name, A record, IN class, TTL=300, RDATA=0.0.0.0
        buf.position(queryEnd)
        buf.putShort(0xC00C.toShort())  // name pointer
        buf.putShort(0x0001)            // type A
        buf.putShort(0x0001)            // class IN
        buf.putInt(300)                 // TTL
        buf.putShort(4)                 // RDLENGTH
        buf.put(0); buf.put(0); buf.put(0); buf.put(0)  // 0.0.0.0

        return fullResponse
    }

    /**
     * Fix #15: builds a DNS SERVFAIL response so the client gets an error
     * instead of a timeout when all upstream servers fail.
     */
    fun buildServFail(originalDnsQuery: ByteArray): ByteArray {
        if (originalDnsQuery.size < 12) return originalDnsQuery
        val response = originalDnsQuery.copyOf(12)
        val buf = ByteBuffer.wrap(response)
        buf.position(2)
        // QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL)
        buf.putShort(0x8182.toShort())
        // QDCOUNT=0, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        buf.position(4)
        buf.putShort(0); buf.putShort(0); buf.putShort(0); buf.putShort(0)
        return response
    }

    private fun findQueryEnd(dns: ByteArray): Int {
        if (dns.size < 12) return -1
        var pos = 12
        while (pos < dns.size) {
            val len = dns[pos].toInt() and 0xFF
            if (len == 0)              { pos++; break }
            if (len and 0xC0 == 0xC0) { pos += 2; break }
            pos += len + 1
        }
        return if (pos + 4 <= dns.size) pos + 4 else -1
    }
}
