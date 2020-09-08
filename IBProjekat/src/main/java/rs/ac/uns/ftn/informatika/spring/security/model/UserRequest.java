package rs.ac.uns.ftn.informatika.spring.security.model;

// DTO koji preuzima podatke iz HTML forme za registraciju
public class UserRequest {

	private Long id;

	private String email;

	private String password;

	private String certificate;
	
	private boolean active;
	
	

	public UserRequest() {
		this.id = (long) 0;
		this.email = "";
		this.password = "";
		this.certificate = "";
		this.active = true;
	}

	public UserRequest(User user) {
		this.id = user.getId();
		this.email = user.getUsername();
		this.password = user.getPassword();
		this.certificate = user.getCertificate();
		this.active = user.isEnabled();
	}

	public boolean isActive() {
		return active;
	}

	public void setActive(boolean active) {
		this.active = active;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getCertificate() {
		return certificate;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}

}
