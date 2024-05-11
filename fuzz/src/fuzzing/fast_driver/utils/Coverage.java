/*
 * Copyright (c) 2017-2018 The Regents of the University of California
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package fuzzing.fast.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.List;
import org.eclipse.collections.api.iterator.IntIterator;
import org.eclipse.collections.api.list.primitive.IntList;
import org.eclipse.collections.impl.list.mutable.primitive.IntArrayList;

public class Coverage {
    private static final int MAX_COVER_COUNT = 4096;  // predefine
    private byte[] coverPoints;
    private int cov_size;

    public Coverage() {
        coverPoints = new byte[MAX_COVER_COUNT];
        cov_size = MAX_COVER_COUNT;
    }

    public Coverage(int covSize) {
        coverPoints = new byte[covSize];
        cov_size = covSize;
    }

    public Coverage(byte[] cov) {
        // coverPoints = new int[cov.length];
        coverPoints = cov.clone();
        cov_size = cov.length;
        // for(int i = 0; i < cov.length; i++) {
        //     coverPoints[i] = cov[i];
        // }
    }

    public Coverage copy() {
        Coverage ret = new Coverage(coverPoints);
        // for (int idx = 0; idx < cov_size; idx++) {
        //     ret.setAtIndex(idx, this.getAtIndex(idx));
        // }
        return ret;
    }

    public byte[] getCoverPoints() {
        return coverPoints;
    }

    public byte getAtIndex(int idx) {
        return coverPoints[idx];
    }

    public void setAtIndex(int idx, byte value) {
        coverPoints[idx] = value;
    }

    public int size() {
        return cov_size;
    }

    public boolean hasNewCoverage(Coverage newCoverage) {
        byte[] newCoverPoints = newCoverage.coverPoints;
        for (int i = 0; i < coverPoints.length; i++) {
            if (coverPoints[i] == 0 && newCoverPoints[i] > 0) {
                return true;
            }
        }
        return false;
    }

    public boolean updateBits(Coverage newCoverage) {
        boolean changed = false;

        // update size of totalCoverage 
        cov_size = newCoverage.size();

        for (int i = 0; i < newCoverage.size(); i++) {
            if(newCoverage.getAtIndex(i) > 0) {
                byte before = coverPoints[i];
                byte after = (byte)(before | hob(newCoverage.getAtIndex(i)));
                if (after != before) {
                    coverPoints[i] = after;
                    changed = true;
                }
            }
        }
        return changed;
    }

    public IntList computeNewCoverage(Coverage baseline) {
        IntArrayList newCoverage = new IntArrayList();

        for (int i = 0; i < cov_size; i++) {
            if (coverPoints[i] > 0 && baseline.getAtIndex(i) == 0) {
                newCoverage.add(i);
            }
        }

        return newCoverage;
    }

    public int getNonZeroCount() {
        int count = 0;
        for (int coverPoint : coverPoints) {
            if (coverPoint > 0) {
                count++;
            }
        }
        return count;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("Coverage counts: \n");
        for (int i = 0; i < coverPoints.length; i++) {
            if (coverPoints[i] == 0) {
                continue;
            }
            sb.append(i);
            sb.append("->");
            sb.append(coverPoints[i]);
            sb.append('\n');
        }
        return sb.toString();
    }

    public int hashCode() {
        return Arrays.hashCode(coverPoints);
    }

    private static byte[] HOB_CACHE = new byte[130];

    /* Computes the highest order bit */
    private static byte computeHob(int num)
    {
        byte ret = 1;
        if (num == 0) {
            return 0;
        }
        while ((num >>= 1) != 0)
            ret <<= 1;
        return ret;
    }

    /** Populates the HOB cache. */
    static {
        for (int i = 0; i < HOB_CACHE.length; i++) {
            HOB_CACHE[i] = computeHob(i);
        }
    }

    /** Returns the highest order bit (perhaps using the cache) */
    private static byte hob(int num) {
        if (num < HOB_CACHE.length) {
            return HOB_CACHE[num];
        } else {
            return computeHob(num);
        }
    }
}
