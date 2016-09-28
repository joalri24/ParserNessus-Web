namespace ParserNessus.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddColumn_NoSeverity : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Reports", "IncludesSeverity0Items", c => c.Boolean(nullable: false));
        }
        
        public override void Down()
        {
            DropColumn("dbo.Reports", "IncludesSeverity0Items");
        }
    }
}
