package io.getarrays.securecapita.enumeration;

/**
 <p>
 Enum that represents a type of a verification:
 <ul>
 <li>
 Creating an account
 </li>
 <li>
 Changing a password
 </li>
 </ul>
 </p>
 */
public enum VerificationType {
    /**
     Creating an account
     */
    ACCOUNT("ACCOUNT"),
    /**
     Changing a password
     */
    PASSWORD("PASSWORD");

    private final String type;

    VerificationType(String type) { this.type = type; }
    /**
     Returns given verification type in a lower case
     */
    public String getType() {
        return this.type.toLowerCase();
    }
}
