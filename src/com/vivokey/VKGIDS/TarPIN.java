/*
 * VKGIDS: A Java Card implementation of the GIDS (Generic Identity
 * Device Specification) specification
 * https://msdn.microsoft.com/en-us/library/windows/hardware/dn642100%28v=vs.85%29.aspx
 * Copyright (C) 2020 VivoKey Technologies
 * 
 * Based on GidsApplet 
 * Copyright (C) 2016  Vincent Le Toux(vincent.letoux@mysmartlogon.com)
 *
 * It has been based on the IsoApplet
 * Copyright (C) 2014  Philip Wendland (wendlandphilip@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */
package com.vivokey.VKGIDS;

import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.PINException;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class TarPIN extends OwnerPIN {
	byte[] shatemp;
	byte[] shatemp2;
	MessageDigest sha224;
	RandomData rand;

	public TarPIN(byte tryLimit, byte maxPINSize) throws PINException {
		super(tryLimit, maxPINSize);
		shatemp = JCSystem.makeTransientByteArray((short) 28, JCSystem.CLEAR_ON_RESET);
		shatemp2 = JCSystem.makeTransientByteArray((short)28, JCSystem.CLEAR_ON_RESET);
		rand = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
		sha224 = MessageDigest.getInstance(MessageDigest.ALG_SHA_224, false);
		
	}
	
	public boolean check(byte[] pin, short offset, byte length) {
		if(super.getTriesRemaining() >= 1) {
			rand.nextBytes(shatemp, (short)0, (short) 28);
			sha224.doFinal(shatemp, (short)0, (short)28, shatemp2, (short)0);
			sha224.doFinal(shatemp2, (short)0, (short)28, shatemp, (short)0);
			sha224.doFinal(shatemp, (short)0, (short)28, shatemp2, (short)0);
			sha224.doFinal(shatemp2, (short)0, (short)28, shatemp, (short)0);
			sha224.doFinal(shatemp, (short)0, (short)28, shatemp2, (short)0);
			sha224.doFinal(shatemp2, (short)0, (short)28, shatemp, (short)0);
			sha224.doFinal(shatemp, (short)0, (short)28, shatemp2, (short)0);
			sha224.doFinal(shatemp2, (short)0, (short)28, shatemp, (short)0);
			sha224.doFinal(shatemp, (short)0, (short)28, shatemp2, (short)0);
			sha224.doFinal(shatemp2, (short)0, (short)28, shatemp, (short)0);
			sha224.doFinal(shatemp, (short)0, (short)28, shatemp2, (short)0);
			sha224.doFinal(shatemp2, (short)0, (short)28, shatemp, (short)0);
			sha224.doFinal(shatemp, (short)0, (short)28, shatemp2, (short)0);
			super.resetAndUnblock();
		}
		return super.check(pin, offset, length);
	}

}
