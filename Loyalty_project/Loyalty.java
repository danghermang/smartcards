/**
 * 
 */
package com.sun.jcclassic.project.loyalty;

import javacard.framework.*;
import javacardx.annotations.*;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = {
	    @StringDef(name = "Package", value = "com.sun.jcclassic.project.loyalty"),
	    @StringDef(name = "AppletName", value = "Loyalty")},
	    // Insert your strings here 
	name = "LoyaltyStrings")
public class Loyalty extends Applet {
	/* constants declaration */

    // code of CLA byte in the command APDU header
    final static byte Loyalty_CLA = (byte) 0x80;

    // codes of INS byte in the command APDU header
    final static byte VERIFY = (byte) 0x20;
    final static byte CREDIT = (byte) 0x30;
    final static byte DEBIT = (byte) 0x40;
    final static byte GET_BALANCE_MONEY = (byte) 0x50;
    final static byte GET_BALANCE_LOYALTY_POINTS = (byte) 0x51;
    final static byte CHANGE_PIN = (byte) 0x70;


    // maximum balance 10000 lei
    final static short MAX_BALANCE = 0x2710;
    // maximum transaction amount 1000 lei
    final static short MAX_TRANSACTION_AMOUNT = 1000;

    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03	;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    // signal the the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    // signal invalid transaction amount
    // amount > MAX_TRANSACTION_AMOUNT or amount < 0
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    // signal the the balance becomes negative
    final static short SW_INSUFFICIENT_MONEY = 0x6A85;
    
    final static short SW_SECURITY_STATUS_NOT_SATISFIED = 0x0101;
    
    final static short SW_INSUFFICIENT_POINTS = 0x6A86;
    
    final static short SW_INSUFFICIENT_POINTS_AND_MONEY = 0x6A87;

    /* instance variables declaration */
    OwnerPIN pin;
    short balanceMoney;
    short balanceLoyaltyPoints = 0;
    short changePIN = 0;
    
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Loyalty(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected Loyalty(byte[] bArray, short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        //bArray reprezinta comanda de selectare applet
        byte pinLen = bArray[bOffset]; // lungime pin

        //initializare pin
        pin.update(bArray, (short) (bOffset + 1), pinLen);
        register();
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        register();
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
    	//citire comanda
        byte[] buffer = apdu.getBuffer();
        
        //check SELECT APDU command
        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // verify the reset of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != Loyalty_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        //Apelare functie in functie de operatia dorita
        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE_MONEY:
                getBalanceMoney(apdu);
                return;
            case GET_BALANCE_LOYALTY_POINTS:
                getBalanceLoyaltyPoints(apdu);
                return;
            case DEBIT:
                debit(apdu);
                return;
            case CREDIT:
                credit(apdu);
                return;
            case VERIFY:
                verify(apdu);
                return;
            case CHANGE_PIN:
                change_pin(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    }
    

    

    @Override
    public boolean select() {
        // The applet declines to be selected
        // if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }

        return true;

    }

    @Override
    public void deselect() {
        pin.reset();
    }

    private void credit(APDU apdu) {
        // verificare acces
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        //Citire Lc
        byte numBytes = buffer[ISO7816.OFFSET_LC];

        // indicate that this APDU has incoming data
        // and receive data starting from the offset
        // ISO7816.OFFSET_CDATA following the 5 header
        // bytes.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // it is an error if the number of data bytes
        // read does not match the number in Lc byte
        if ((numBytes != 2) || (byteRead != 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // get the credit amount
        short creditAmount = (short) (((buffer[ISO7816.OFFSET_CDATA] & 0xFF) << 8) | (buffer[ISO7816.OFFSET_CDATA + 1] & 0xFF));

        // check the credit amount
        if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        // check the new balance
        if ((short) (balanceMoney + creditAmount) > MAX_BALANCE) {
            ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
        }

        // credit the amount
        balanceMoney = (short) (balanceMoney + creditAmount);

    }
    
    private void debit(APDU apdu) {
        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        byte numBytes = (buffer[ISO7816.OFFSET_LC]);

        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        /**
         * Campul data pentru plata cu bani:   LC:0x03 | Tip_Plata: 0x01  Suma_Bani: 0x01 0x00
         * Campul data pentru plata cu puncte: LC:0x03 | Tip_Plata: 0x02  Suma_Bani: 0x01 0x00
         * Campul data pentru plata prin combinatie: LC:0x07 | Tip_Plata: 0x03  Suma_Totala: 0x02 0x00 Suma_Bani: 0x01 0x00 Suma_Bani_Puncte: 0x01
         */
        if (!((numBytes == 3 && byteRead == 3) || (numBytes == 7 && byteRead == 7))) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        byte commandId = buffer[ISO7816.OFFSET_CDATA];
        if((numBytes == 3 && byteRead == 3)){
        	if(commandId == 0x01)
        		moneyDebit(apdu);
        	else if(commandId == 0x02)
    			loyaltyPointsDebit(apdu);
        	else
        		ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        		
        }
        
        if((numBytes == 7 && byteRead == 7)){
        	if(commandId == 0x03)
        		combinationDebit(apdu);
        	else
        		ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

	private void moneyDebit(APDU apdu) {
		//		
		// get debit amount
		byte[] buffer = apdu.getBuffer();
		short debitAmount =  ((short) (((buffer[ISO7816.OFFSET_CDATA+1] & 0xFF) << 8) | (buffer[ISO7816.OFFSET_CDATA + 2] & 0xFF)));

		// check debit amount
		if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}

		// check the new balance
		if ((short) (balanceMoney - debitAmount) < (short) 0) {
			ISOException.throwIt(SW_INSUFFICIENT_MONEY);
		}

		balanceMoney = (short) (balanceMoney - debitAmount);

		// add loyalty points
		balanceLoyaltyPoints += (short) ((short) (debitAmount - ((debitAmount % 10))) / 10);
	}
    
	private void loyaltyPointsDebit(APDU apdu) {
		// get debit amount
		byte[] buffer = apdu.getBuffer();
		short debitAmount = ((short) (((buffer[ISO7816.OFFSET_CDATA+1] & 0xFF) << 8) | (buffer[ISO7816.OFFSET_CDATA + 2] & 0xFF)));
		
		if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}
		
		// check exist sufficient number of points
		if ((short) (balanceLoyaltyPoints - debitAmount) < (short) 0) {
			ISOException.throwIt(SW_INSUFFICIENT_POINTS);
		}

		balanceLoyaltyPoints = (short) (balanceLoyaltyPoints - debitAmount);
	}
    
    private void combinationDebit(APDU apdu){
    	byte[] buffer = apdu.getBuffer();
    	
		short totalDebitAmount = ((short) (((buffer[ISO7816.OFFSET_CDATA + 1] & 0xFF) << 8) | (buffer[ISO7816.OFFSET_CDATA + 2] & 0xFF)));
		
		short moneyDebitAmount = ((short) (((buffer[ISO7816.OFFSET_CDATA + 3] & 0xFF) << 8) | (buffer[ISO7816.OFFSET_CDATA + 4] & 0xFF)));
		
		short pointsDebitAmount = ((short) (((buffer[ISO7816.OFFSET_CDATA + 5] & 0xFF) << 8) | (buffer[ISO7816.OFFSET_CDATA + 6] & 0xFF)));

		if(totalDebitAmount != (short)(moneyDebitAmount + pointsDebitAmount))
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		// check debit amount
		
		
		if ((totalDebitAmount > MAX_TRANSACTION_AMOUNT) || (totalDebitAmount < 0)) {
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}
		
		if ((short) (balanceLoyaltyPoints - pointsDebitAmount) < (short) 0 && (short) (balanceMoney - moneyDebitAmount) < (short) 0)
			ISOException.throwIt(SW_INSUFFICIENT_POINTS_AND_MONEY);
		
		if ((short) (balanceLoyaltyPoints - pointsDebitAmount) < (short) 0) {
			ISOException.throwIt(SW_INSUFFICIENT_POINTS);
		}
		
		if ((short) (balanceMoney - moneyDebitAmount) < (short) 0) {
			ISOException.throwIt(SW_INSUFFICIENT_MONEY);
		}
		
		balanceLoyaltyPoints = (short) (balanceLoyaltyPoints - pointsDebitAmount);
		balanceMoney = (short) (balanceMoney - moneyDebitAmount);
		//Colectare puncte
		balanceLoyaltyPoints += (short) ((short) (moneyDebitAmount - ((moneyDebitAmount % 10))) / 10);
    }
    
    private void getBalanceMoney(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();
        
        short le = apdu.setOutgoing();

        if (le < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        apdu.setOutgoingLength((byte) 2);

        buffer[0] = (byte) (balanceMoney >> 8);
        buffer[1] = (byte) (balanceMoney & 0xFF);

        apdu.sendBytes((short) 0, (short) 2);
    }

    private void getBalanceLoyaltyPoints(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();
        short le = apdu.setOutgoing();

        if (le < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        apdu.setOutgoingLength((byte) 2);

        // move the balance data into the APDU buffer
        // starting at the offset 0
        buffer[0] = (byte) (balanceLoyaltyPoints >> 8);
        buffer[1] = (byte) (balanceLoyaltyPoints & 0xFF);

        // send the 2-byte balance at the offset
        // 0 in the apdu buffer
        apdu.sendBytes((short) 0, (short) 2);
    }

    
    private void verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    }
    
    
    private void change_pin(APDU apdu){
    	//data
    	//dimensiune_pin_vechi dimensiune_pin_nou pin_nou pin_vechi
        if(pin.getTriesRemaining() == 0)
        	ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buffer = apdu.getBuffer();
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        byte dimensiunePinVechi = buffer[ISO7816.OFFSET_CDATA];
        byte dimensiunePinNou = buffer[ISO7816.OFFSET_CDATA + 1];
        
        if ((numBytes != (byte)(dimensiunePinNou + dimensiunePinVechi + 2))){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        byte [] oldPin = new byte[dimensiunePinVechi];
        for(byte i = 0; i < dimensiunePinVechi; i++)
        	oldPin[i] = buffer[ISO7816.OFFSET_CDATA + (byte)(i+2)];
        
        byte [] newPin = new byte[dimensiunePinNou];
        for(byte i = 0; i < dimensiunePinNou; i++)
        	newPin[i] = buffer[ISO7816.OFFSET_CDATA + (byte)(i+2+dimensiunePinVechi)]; 
        
        
        if (pin.check(newPin, (short)0, dimensiunePinNou) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }else{
            pin.update(oldPin, (short)0, (byte)dimensiunePinVechi);
        }
    }

}
