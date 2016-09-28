namespace ParserNessus.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class UpdateReportModel : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Reports", "Date", c => c.DateTime(nullable: false));
            AddColumn("dbo.Reports", "Comments", c => c.String());
            DropColumn("dbo.Reports", "ClientName");
        }
        
        public override void Down()
        {
            AddColumn("dbo.Reports", "ClientName", c => c.String());
            DropColumn("dbo.Reports", "Comments");
            DropColumn("dbo.Reports", "Date");
        }
    }
}
