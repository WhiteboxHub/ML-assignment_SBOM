from sqlalchemy import create_engine, Column, Integer, String, Text, Date, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

# Define the database URL (replace with your actual database URL)
DATABASE_URL = "postgresql://postgres:password@localhost:5432/aisbom"

# Create the engine
engine = create_engine(DATABASE_URL)

# Create a base class for declarative models
Base = declarative_base()

# Define the Vendors table
class Vendor(Base):
    __tablename__ = 'vendors'  # Corrected to double underscores
    vendor_id = Column(Integer, primary_key=True, autoincrement=True)
    vendor_name = Column(String(100), nullable=False)
    contact_info = Column(String(255))

    # Relationship to Products
    products = relationship('Product', back_populates='vendor')

# Define the Products table
class Product(Base):
    __tablename__ = 'products'  # Corrected to double underscores
    product_id = Column(Integer, primary_key=True, autoincrement=True)
    product_name = Column(String(100), nullable=False)
    version = Column(String(50), nullable=False)
    vendor_id = Column(Integer, ForeignKey('vendors.vendor_id'))
    release_date = Column(Date)

    # Relationship to Vendor
    vendor = relationship('Vendor', back_populates='products')
    # Relationship to Vulnerabilities and Fixes
    vulnerabilities = relationship('Vulnerability', back_populates='product')
    fixes = relationship('Fix', back_populates='product')

# Define the Vulnerabilities table
class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'  # Corrected to double underscores
    vulnerability_id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), unique=True, nullable=False)
    description = Column(Text)
    severity = Column(String(20))
    affected_product_id = Column(Integer, ForeignKey('products.product_id'))

    # Relationship to Product and Fixes
    product = relationship('Product', back_populates='vulnerabilities')
    fixes = relationship('Fix', back_populates='vulnerability')

# Define the Fixes table
class Fix(Base):
    __tablename__ = 'fixes'  # Corrected to double underscores
    fix_id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.vulnerability_id'))
    fixed_product_id = Column(Integer, ForeignKey('products.product_id'))
    fix_description = Column(Text)

    # Relationships to Vulnerability and Product
    vulnerability = relationship('Vulnerability', back_populates='fixes')
    product = relationship('Product', back_populates='fixes')

# Create the tables in the database
try:
    Base.metadata.create_all(engine)
    print("Tables created successfully!")
except Exception as e:
    print(f"An error occurred: {e}")

# Create a session
Session = sessionmaker(bind=engine)
session = Session()
